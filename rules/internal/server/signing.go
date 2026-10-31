package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/pii-shield/pii-shield/rules/internal/signing"
	"github.com/pii-shield/pii-shield/rules/internal/store"
)

// serveSignature answers GET .../policy.json.sig with the signature of the
// publication the set serves, under the same token as the file. The body
// is the statement with the key id and the signature; the operator rebuilds
// the statement from the file it pulled and checks it. An unsigned
// publication is 404, which a cluster that requires signatures refuses.
func (s *Server) serveSignature(w http.ResponseWriter, r *http.Request) {
	acc, ok := s.pullAccess(w, r)
	if !ok {
		return
	}
	pub, err := s.store.LatestPublication(r.Context(), acc.Set.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotPublished) {
			s.fail(w, http.StatusNotFound, "the rule set has no published version")
			return
		}
		s.internal(w, err)
		return
	}
	if pub.Signature == "" {
		s.fail(w, http.StatusNotFound, "the published version is not signed")
		return
	}
	v, err := s.store.Published(r.Context(), acc.Set.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	st := signing.For(acc.Org.Slug+"/"+acc.Set.Slug, pub.Seq, v.Revision, v.Content)
	s.json(w, http.StatusOK, map[string]any{
		"set": st.Set, "publication": st.Publication, "revision": st.Revision, "sha256": st.SHA256,
		"keyId": pub.KeyID, "signature": pub.Signature,
	})
}

type signingKeyRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

func (s *Server) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	org, ok := s.org(w, r)
	if !ok {
		return
	}
	keys, err := s.store.ListSigningKeys(r.Context(), org.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{"keys": keys})
}

// addSigningKey registers the public half of a publisher's key. From then
// on the organization's publications must be signed.
func (s *Server) addSigningKey(w http.ResponseWriter, r *http.Request) {
	org, ok := s.org(w, r)
	if !ok {
		return
	}
	var req signingKeyRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.Name == "" {
		s.fail(w, http.StatusBadRequest, `"name" is required: whose key it is and where it lives`)
		return
	}
	pk, err := signing.ParsePublicKey(req.PublicKey)
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	k, err := s.store.AddSigningKey(r.Context(), org.ID, signing.KeyID(pk), req.Name, signing.FormatPublicKey(pk), authorOf(r, ""))
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.log.Info("signing key added", "org", org.Slug, "key", k.KeyID, "name", k.Name, "by", k.CreatedBy)
	s.json(w, http.StatusCreated, k)
}

func (s *Server) revokeSigningKey(w http.ResponseWriter, r *http.Request) {
	org, ok := s.org(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "key id must be a number")
		return
	}
	if err := s.store.RevokeSigningKey(r.Context(), org.ID, id); err != nil {
		s.storeError(w, err)
		return
	}
	s.log.Info("signing key revoked", "org", org.Slug, "id", id)
	w.WriteHeader(http.StatusNoContent)
}
