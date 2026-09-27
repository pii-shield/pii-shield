import os
import sys
import json
from dataclasses import dataclass, asdict
from typing import List, Optional
from wasmtime import Engine, Linker, Store, Config, Module, WasiConfig

@dataclass
class PiiShieldConfig:
    entropy_threshold: Optional[float] = None
    salt: Optional[str] = None
    confidence_score: Optional[float] = None
    fail_policy: str = "open"
    # Minimum candidate token length before entropy checks apply.
    min_secret_length: Optional[int] = None
    # Key names whose values are always redacted (case-insensitive). Replaces the defaults.
    sensitive_keys: Optional[List[str]] = None
    # Disable English bigram analysis (useful for non-English logs).
    disable_bigram_check: Optional[bool] = None
    # Enable experimental statistical adaptive-threshold mode.
    adaptive_threshold: Optional[bool] = None
    # Emit [HIDDEN:<type>:<hash>] markers (type is card/key/context/url/regex/entropy).
    entity_type_labels: Optional[bool] = None
    # Regex patterns matched against key names to detect sensitive keys.
    sensitive_key_patterns: Optional[List[str]] = None
    # Custom rules forcing redaction: [{"pattern": ..., "name": ...}].
    custom_regexes: Optional[List[dict]] = None
    # Whitelist rules exempting matching tokens: [{"pattern": ..., "name": ...}].
    safe_regexes: Optional[List[dict]] = None

class PiiShield:
    def __init__(self, config: PiiShieldConfig = None, wasm_path: str = None):
        self.config = config or PiiShieldConfig()
        
        if not wasm_path:
            # Default to the root of the plugin for testing, or inside the package
            wasm_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "pii-shield-wasi.wasm")
            if not os.path.exists(wasm_path):
                wasm_path = os.path.join(os.path.dirname(__file__), "pii-shield-wasi.wasm")
        
        cfg = Config()
        if sys.platform == "darwin":
            # wasmtime's default macOS trap handler sets Mach exception ports on the
            # calling thread. Apple-signed interpreters (/usr/bin/python3) guard that
            # port, and the kernel SIGKILLs the process on the first wasm call.
            # Signal-based trap handling works in every interpreter.
            cfg.macos_use_mach_ports = False
        self.engine = Engine(cfg)
        self.linker = Linker(self.engine)
        
        # Configure WASI
        self.linker.define_wasi()
        self.store = Store(self.engine)
        wasi_cfg = WasiConfig()
        wasi_cfg.inherit_stdout()
        wasi_cfg.inherit_stderr()
        wasi_cfg.inherit_env()
        self.store.set_wasi(wasi_cfg)
        
        self.module = Module.from_file(self.engine, wasm_path)
        self.instance = self.linker.instantiate(self.store, self.module)
        
        # Go 1.24+ wasi reactors must be initialized
        exports = self.instance.exports(self.store)
        if "_initialize" in exports:
            exports["_initialize"](self.store)
        
        # Extracted functions
        self.memory = exports["memory"]
        self.allocate = exports["allocate"]
        self.free_mem = exports["free"]
        self.init_config = exports["init_config"]
        self.redact_fn = exports["redact"]
        
        # Sync config
        cfg_dict = {}
        if self.config.entropy_threshold is not None:
            cfg_dict["entropy_threshold"] = self.config.entropy_threshold
        if self.config.salt is not None:
            cfg_dict["salt"] = self.config.salt
        if self.config.confidence_score is not None:
            cfg_dict["confidence_score"] = self.config.confidence_score
        if self.config.min_secret_length is not None:
            cfg_dict["min_secret_length"] = self.config.min_secret_length
        if self.config.sensitive_keys is not None:
            cfg_dict["sensitive_keys"] = self.config.sensitive_keys
        if self.config.disable_bigram_check is not None:
            cfg_dict["disable_bigram_check"] = self.config.disable_bigram_check
        if self.config.adaptive_threshold is not None:
            cfg_dict["adaptive_threshold"] = self.config.adaptive_threshold
        if self.config.entity_type_labels is not None:
            cfg_dict["entity_type_labels"] = self.config.entity_type_labels
        if self.config.sensitive_key_patterns is not None:
            cfg_dict["sensitive_key_patterns"] = self.config.sensitive_key_patterns
        if self.config.custom_regexes is not None:
            cfg_dict["custom_regexes"] = self.config.custom_regexes
        if self.config.safe_regexes is not None:
            cfg_dict["safe_regexes"] = self.config.safe_regexes

        cfg_json = json.dumps(cfg_dict).encode("utf-8")
        if len(cfg_json) > 0:
            cfg_ptr = self.allocate(self.store, len(cfg_json))
            if cfg_ptr != 0:
                self.memory.write(self.store, cfg_json, cfg_ptr)
                self.init_config(self.store, cfg_ptr, len(cfg_json))
                self.free_mem(self.store, cfg_ptr, len(cfg_json))

    def redact(self, input_str: str) -> str:
        if not input_str:
            return input_str
            
        try:
            input_bytes = input_str.encode('utf-8')
            length = len(input_bytes)
            
            ptr = self.allocate(self.store, length)
            if ptr == 0:
                if self.config.fail_policy == "closed":
                    return "[PII_SHIELD_DROP: FATAL_ERROR]"
                return input_str
                
            self.memory.write(self.store, input_bytes, ptr)
            
            packed_result = self.redact_fn(self.store, ptr, length)
            
            # The result is uint64: ptr in high 32 bits, len in low 32 bits
            result_ptr = (packed_result >> 32) & 0xFFFFFFFF
            result_len = packed_result & 0xFFFFFFFF
            
            result_str = input_str
            if result_ptr != 0 and result_len != 0:
                # Need to read memory
                result_bytes = self.memory.read(self.store, result_ptr, result_ptr + result_len)
                result_str = result_bytes.decode('utf-8')
                self.free_mem(self.store, result_ptr, result_len)
                
            self.free_mem(self.store, ptr, length)
            return result_str
            
        except Exception:
            if self.config.fail_policy == "closed":
                return "[PII_SHIELD_DROP: FATAL_ERROR]"
            return input_str
