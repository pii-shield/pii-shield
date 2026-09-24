package scanner

import (
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"testing"
)

// TestF6ThresholdSweep asks whether one entropy threshold per length bucket
// beats the global one on the frozen F6 corpus. It runs end to end: for each
// bucket and each threshold the keyless check from TestEntropyThresholdCorpus
// is repeated with that EntropyThreshold. Thresholds are fitted on one half of
// the corpus (split by FNV hash of the token) and reported on the other, both
// ways round, so the numbers are held out. Off by default:
//
//	F6_SWEEP=1 go test ./pkg/scanner/ -run TestF6ThresholdSweep -v
func TestF6ThresholdSweep(t *testing.T) {
	if os.Getenv("F6_SWEEP") == "" {
		t.Skip("set F6_SWEEP=1 to run the F6 threshold sweep")
	}
	corpus, err := readF6Corpus()
	if err != nil {
		t.Fatal(err)
	}

	var ths []float64
	for x := 250; x <= 500; x += 5 {
		ths = append(ths, float64(x)/100)
	}
	nb := len(f6Buckets)
	bucketIdx := map[string]int{}
	for i, b := range f6Buckets {
		bucketIdx[b.name] = i
	}

	// hit[half][bucket][threshold] = {tp, fp}; pos/neg = totals per half and bucket.
	type tf struct{ tp, fp int }
	hit := [2][][]tf{}
	pos := [2][]int{}
	for h := 0; h < 2; h++ {
		hit[h] = make([][]tf, nb)
		for b := range hit[h] {
			hit[h][b] = make([]tf, len(ths))
		}
		pos[h] = make([]int, nb)
	}
	half := func(tok string) int {
		f := fnv.New32a()
		f.Write([]byte(tok))
		return int(f.Sum32() & 1)
	}
	baseIdx := -1
	for ti, th := range ths {
		if fmt.Sprintf("%.2f", th) == "3.60" {
			baseIdx = ti
		}
		cfg := campaignConfig()
		cfg.EntropyThreshold = th
		s := NewScanner(cfg)
		for _, c := range corpus {
			if c.label == "ambiguous" {
				continue
			}
			h, b := half(c.token), bucketIdx[f6Bucket(c.token)]
			if ti == 0 && c.label == "secret" {
				pos[h][b]++
			}
			out := s.ScanAndRedact("event " + c.token + " done")
			f := strings.Fields(out)
			if len(f) < 2 || f[1] != c.token {
				if c.label == "secret" {
					hit[h][b][ti].tp++
				} else {
					hit[h][b][ti].fp++
				}
			}
		}
	}

	// fit returns the per-bucket threshold index that maximises TP with FP <=
	// budget (minFP=false), or minimises FP with TP >= need (minFP=true).
	fit := func(h int, budget int, minFP bool) []int {
		const inf = 1 << 30
		if !minFP {
			// dp[b][f] = best TP over buckets < b using exactly <= f FPs.
			dp := make([]int, budget+1)
			choice := make([][]int, nb)
			for b := 0; b < nb; b++ {
				next := make([]int, budget+1)
				choice[b] = make([]int, budget+1)
				for f := 0; f <= budget; f++ {
					next[f] = -inf
					for ti := range ths {
						c := hit[h][b][ti]
						if c.fp <= f && dp[f-c.fp] > -inf && dp[f-c.fp]+c.tp > next[f] {
							next[f] = dp[f-c.fp] + c.tp
							choice[b][f] = ti
						}
					}
				}
				dp = next
			}
			out := make([]int, nb)
			f := budget
			for b := nb - 1; b >= 0; b-- {
				out[b] = choice[b][f]
				f -= hit[h][b][out[b]].fp
			}
			return out
		}
		// minFP: dp over TP needed, value = min FP.
		need := budget
		dp := make([]int, need+1)
		for i := 1; i <= need; i++ {
			dp[i] = inf
		}
		choice := make([][]int, nb)
		for b := 0; b < nb; b++ {
			next := make([]int, need+1)
			choice[b] = make([]int, need+1)
			for r := 0; r <= need; r++ {
				next[r] = inf
				for ti := range ths {
					c := hit[h][b][ti]
					prev := r - c.tp
					if prev < 0 {
						prev = 0
					}
					if dp[prev] < inf && dp[prev]+c.fp < next[r] {
						next[r] = dp[prev] + c.fp
						choice[b][r] = ti
					}
				}
			}
			dp = next
		}
		out := make([]int, nb)
		r := need
		for b := nb - 1; b >= 0; b-- {
			out[b] = choice[b][r]
			r -= hit[h][b][out[b]].tp
			if r < 0 {
				r = 0
			}
		}
		return out
	}
	eval := func(h int, sel []int) (tp, fp, p int) {
		for b := 0; b < nb; b++ {
			tp += hit[h][b][sel[b]].tp
			fp += hit[h][b][sel[b]].fp
			p += pos[h][b]
		}
		return
	}
	base := make([]int, nb)
	for b := range base {
		base[b] = baseIdx
	}

	var rep strings.Builder
	for h := 0; h < 2; h++ {
		other := 1 - h
		btp, bfp, _ := eval(h, base)
		otp, ofp, op := eval(other, base)
		fmt.Fprintf(&rep, "\nfit on half %d, report on half %d. Baseline 3.60 on held-out: TP %d/%d (%.1f%%) FP %d\n", h, other, otp, op, pct(otp, op), ofp)
		for _, mode := range []struct {
			name  string
			minFP bool
			arg   int
		}{{"(a) max recall, FP <= baseline", false, bfp}, {"(b) min FP, TP >= baseline", true, btp}} {
			sel := fit(h, mode.arg, mode.minFP)
			ftp, ffp, fpos := eval(h, sel)
			htp, hfp, hp := eval(other, sel)
			fmt.Fprintf(&rep, "  %s\n    thresholds:", mode.name)
			for b, ti := range sel {
				fmt.Fprintf(&rep, " %s=%.2f", f6Buckets[b].name, ths[ti])
			}
			fmt.Fprintf(&rep, "\n    fitted half: TP %d/%d (%.1f%%) FP %d\n    held-out:    TP %d/%d (%.1f%%) FP %d\n",
				ftp, fpos, pct(ftp, fpos), ffp, htp, hp, pct(htp, hp), hfp)
		}
	}
	// Per-bucket curve on the whole corpus, for reading by eye.
	rep.WriteString("\nper bucket, whole corpus: threshold -> recall% / FPs\n")
	for b := 0; b < nb; b++ {
		fmt.Fprintf(&rep, "%s:", f6Buckets[b].name)
		for ti := 0; ti < len(ths); ti += 5 {
			p := pos[0][b] + pos[1][b]
			tp := hit[0][b][ti].tp + hit[1][b][ti].tp
			fp := hit[0][b][ti].fp + hit[1][b][ti].fp
			fmt.Fprintf(&rep, " %.2f->%.0f/%d", ths[ti], pct(tp, p), fp)
		}
		rep.WriteString("\n")
	}
	t.Log(rep.String())
}
