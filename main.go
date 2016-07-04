/* main.go */

package main
import (
    "net/http"
    "log"
    "fmt"
    "time"
    "bytes"
    "errors"
    "encoding/binary"
    "encoding/json"
    "golang.org/x/crypto/openpgp"
    "math/rand"
    "encoding/base64"
    "strings"
    //openpgp_errors "golang.org/x/crypto/openpgp/errors"
    "github.com/boltdb/bolt"
)

/* BoltDB Schema:

fingerprints: {
    fingerprint1: pub1,
    fingerprint2: pub2,
    ...
}

challenges: {
    pub1: {
        'send': {   // Holds messages while challenge pending
            challenge1: {
                'toPub': toPub,
                'ciphertext': ciphertext,
                'dateCreated' dateCreated
            },
            ...
        },
        'refresh': {
            challenge1: "",
            challenge2: "",
            ...
        }
    },
    ...
}

messages: {
    toPub1: {
        msgId1: {
            'fromPub': fromPub,
            'ciphertext': ciphertext,
            'dateCreated' dateCreated
        },
        ...
    },
    ...
}

*/

func main() {
    rand.Seed(time.Now().UnixNano())

    db, err := bolt.Open("chat27.db", 0600, nil)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    db.Update(func(tx *bolt.Tx) error {
        tx.CreateBucketIfNotExists([]byte("fingerprints"))
        tx.CreateBucketIfNotExists([]byte("messages"))
        tx.CreateBucketIfNotExists([]byte("challenges"))
        return nil
    })

    fs := http.FileServer(http.Dir("static"))
    http.Handle("/static/", http.StripPrefix("/static/", fs))
    http.HandleFunc("/sendChallenge/", sendChallengeHandler(db))
    http.HandleFunc("/sendResponse/", sendResponseHandler(db))
    http.HandleFunc("/refreshChallenge/", refreshChallengeHandler(db))
    http.HandleFunc("/refreshResponse/", refreshResponseHandler(db))
    http.HandleFunc("/registerPubKey/", registerPubKeyHandler(db))
    http.HandleFunc("/lookupPubKey/", lookupPubKeyHandler(db))
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "static/chat27.html")
    })

    err = http.ListenAndServe(":11994", nil)
    if err != nil {
        log.Fatal(err)
    }
}

/* POST /sendChallenge/ */
func sendChallengeHandler(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
    return  func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "POST required", http.StatusMethodNotAllowed)
            return
        }

        //TODO check key validity?
        fromPub :=  r.PostFormValue("fromPub")
        toPub := r.PostFormValue("toPub")
        ciphertext := r.PostFormValue("ciphertext")

        if len(fromPub) == 0 || len(toPub) == 0 || len(ciphertext) == 0 {
            http.Error(w, "Missing parameter(s)", http.StatusBadRequest)
            return
        }

        rb := make([]byte, 32)
        _, err := rand.Read(rb)
        challenge := base64.URLEncoding.EncodeToString(rb)

        err = db.Update(func(tx *bolt.Tx) error {
            challenges := tx.Bucket([]byte("challenges"))
            if challenges == nil {
                return errors.New("No bucket 'challenges'")
            }

            p, err := challenges.CreateBucketIfNotExists([]byte(fromPub))
            if err != nil {
                return err
            }

            s, err := p.CreateBucketIfNotExists([]byte("send"))
            if err != nil {
                return err
            }

            c, err := s.CreateBucket([]byte(challenge))
            if err != nil {
                return err
            }

            /*  Message is pending. Will be moved to 'messages' bucket once challenge accepted */
            if err = c.Put([]byte("toPub"), []byte(toPub)); err != nil {
                return err
            }
            if err = c.Put([]byte("ciphertext"), []byte(ciphertext)); err != nil {
                return err
            }
            if err = c.Put([]byte("dateCreated"), []byte(time.Now().Format(time.RFC3339))); err != nil {
                return err
            }
            return nil
        })

        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
        } else {
            w.Write([]byte(challenge))
        } 
    }
}

/* POST /sendResponse/ */
func sendResponseHandler(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
    return  func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "POST required", http.StatusMethodNotAllowed)
            return
        }

        fromPub :=  r.PostFormValue("fromPub")
        challenge := r.PostFormValue("challenge")
        signature := r.PostFormValue("signature")

        if len(fromPub) == 0 || len(challenge) == 0 || len(signature) == 0 {
            http.Error(w, "Missing parameter(s)", http.StatusBadRequest)
            return
        }

        err := db.Update(func(tx *bolt.Tx) error {
            challenges := tx.Bucket([]byte("challenges"))
            if challenges == nil {
                return errors.New("No bucket 'challenges'")
            }

            p := challenges.Bucket([]byte(fromPub))
            if p == nil {
                return errors.New("Bucket not found")
            }

            s := p.Bucket([]byte("send"))
            if s == nil {
                return errors.New("Bucket 'send' not found")
            }

            c := s.Bucket([]byte(challenge))
            if c == nil {
                return errors.New("No bucket for challenge string: " + challenge)
            }

            valid, _ := verifySignature(fromPub, signature, challenge)
            if !valid {
                return errors.New("Invalid signature. Challenge failed")
            }

            /* Challenge accepted. Move message into 'messages' bucket */
            toPub := c.Get([]byte("toPub"))
            ciphertext := c.Get([]byte("ciphertext"))
            dateCreated := c.Get([]byte("dateCreated"))
            s.DeleteBucket([]byte(challenge))

            messages := tx.Bucket([]byte("messages"))
            if messages == nil {
                return errors.New("No bucket 'messages'")
            }

            toBucket, err := messages.CreateBucketIfNotExists([]byte(toPub))
            if err != nil {
                return err
            }

            id, _ := toBucket.NextSequence()    // Can't error in db.Update 
            msg, err := toBucket.CreateBucket(uint64ToBytes(id))
            if err != nil {
                return err
            }

            if err = msg.Put([]byte("fromPub"), []byte(fromPub)); err != nil {
                return err
            }
            if err = msg.Put([]byte("ciphertext"), []byte(ciphertext)); err != nil {
                return err
            }
            if err = msg.Put([]byte("dateCreated"), []byte(dateCreated)); err != nil {
                return err
            }
            return nil
        })

        if err != nil {
            w.WriteHeader(http.StatusBadRequest)
        } else {
            w.WriteHeader(http.StatusOK)
        }
    }
}

/* POST /refreshChallenge/ */
func refreshChallengeHandler(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
    return  func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "POST required", http.StatusMethodNotAllowed)
            return
        }

        pub := r.PostFormValue("pub")
        if len(pub) == 0 {
            http.Error(w, "Missing parameter 'pub'", http.StatusBadRequest)
            return
        }

        rb := make([]byte, 32)
        _, err := rand.Read(rb)
        challenge := base64.URLEncoding.EncodeToString(rb)

        err = db.Update(func(tx *bolt.Tx) error {
            challenges := tx.Bucket([]byte("challenges"))
            if challenges == nil {
                return errors.New("No bucket 'challenges'")
            }

            p, err := challenges.CreateBucketIfNotExists([]byte(pub))
            if err != nil {
                return err
            }

            r, err := p.CreateBucketIfNotExists([]byte("refresh"))
            if err != nil {
                return err
            }
            return r.Put([]byte(challenge), []byte(""))
        })

        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
        } else {
            w.Write([]byte(challenge))
        }
    }
}

/* POST /refreshResponse/ */
func refreshResponseHandler(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
    return  func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "POST required", http.StatusMethodNotAllowed)
            return
        }

        pub := r.PostFormValue("pub")
        challenge := r.PostFormValue("challenge")
        signature := r.PostFormValue("signature")

        if len(pub) == 0 || len(signature) == 0 || len(challenge) == 0 {
            http.Error(w, "Missing parameter(s)", http.StatusBadRequest)
            return
        }

        type Resp struct {
            FromPubs []string
            Messages []string
            Dates []string
        }

        fromPubs := []string{}
        messages := []string{}
        dates := []string{}

        err := db.Update(func(tx *bolt.Tx) error {
            challenges := tx.Bucket([]byte("challenges"))
            if challenges == nil {
                return errors.New("No bucket 'challenges'")
            }

            p := challenges.Bucket([]byte(pub))
            if p == nil {
                return errors.New("Bucket not found")
            }

            r := p.Bucket([]byte("refresh"))
            if r == nil {
                return errors.New("Bucket 'refresh' not found")
            }

            if r.Get([]byte(challenge)) == nil {
                return errors.New("No bucket for challenge string: " + challenge)
            }

            valid, _ := verifySignature(pub, signature, challenge)
            if !valid {
                return errors.New("Invalid signature. Challenge failed")
            }

            /* Challenge accepted */
            r.Delete([]byte(challenge))

            allMsgs := tx.Bucket([]byte("messages"))
            if allMsgs == nil {
                return errors.New("No bucket 'messages'")
            }

            theirMessages := allMsgs.Bucket([]byte(pub))
            if theirMessages == nil {
                return nil  /* No new messages */
            }

            theirMessages.ForEach(func(k, _ []byte) error {
                msg := theirMessages.Bucket(k)
                fromPub := msg.Get([]byte("fromPub"))
                ciphertext := msg.Get([]byte("ciphertext"))
                dateCreated := msg.Get([]byte("dateCreated"))

                if fromPub == nil || ciphertext == nil || dateCreated == nil {
                    /* Corrupted message */
                } else {
                    fromPubs = append(fromPubs, string(fromPub))
                    messages = append(messages, string(ciphertext))
                    dates = append(dates, string(dateCreated))
                }
                return nil
            })

            allMsgs.DeleteBucket([]byte(pub))
            return nil
        })

        // TODO our fault or their fault
        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
            return
        }

        json, err := json.Marshal(Resp{fromPubs, messages, dates})
        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
        } else {
            w.Header().Set("Content-Type", "application/json")
            w.Write(json)
        }
    }
}

/* POST /registerPubKey/ */
func registerPubKeyHandler(db *bolt.DB) http.HandlerFunc {
    return  func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "POST required", http.StatusMethodNotAllowed)
            return
        }

        pub := r.PostFormValue("pub")
        keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(pub))
        if err != nil{
            http.Error(w, "Invalid public key", http.StatusBadRequest)
            return
        }

        fingerprint := fmt.Sprintf("%X", keyring[0].PrimaryKey.Fingerprint)
        fingerprint = strings.ToLower(fingerprint)

        err = db.Update(func(tx *bolt.Tx) error {
            fingers := tx.Bucket([]byte("fingerprints"))
            if fingers == nil {
                return errors.New("No bucket 'fingerprints'")
            }

            if fingers.Get([]byte(fingerprint)) != nil {
                return errors.New("Fingerprint already registerd")
            }
            return fingers.Put([]byte(fingerprint), []byte(pub))
        })

        if err != nil {
            w.WriteHeader(http.StatusBadRequest)
        } else {
            w.WriteHeader(http.StatusOK)
        }
    }
}

/* GET /lookupFingerprint/ */
func lookupPubKeyHandler(db *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
    return  func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            http.Error(w, "GET required", http.StatusMethodNotAllowed)
            return
        }

        fingerprint := r.FormValue("fingerprint")
        if len(fingerprint) == 0 {
            http.Error(w, "Missing parameter 'fingerprint'", http.StatusBadRequest)
            return
        }

        var pub []byte
        err := db.View(func(tx *bolt.Tx) error {
            fingers := tx.Bucket([]byte("fingerprints"))
            if fingers == nil {
                return errors.New("No bucket 'fingerprints'")
            }
            pub = fingers.Get([]byte(fingerprint))
            return nil
        })

        if err != nil {
            w.WriteHeader(http.StatusInternalServerError)
        } else if pub == nil {
            http.Error(w, "Fingerprint not found", http.StatusBadRequest)
        } else {
            w.Write(pub)
        }
    }
}

func verifySignature(pub string, signature string, challenge string)(bool, error) {
    keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(pub))
    if err != nil {
        return false, err   /* Failed to parse public key */
    }

    entity, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewBufferString(challenge), bytes.NewBufferString(signature))
    if err != nil {
        return false, err   /* openpgp_errors.ErrUnknownIssuer = Signature does not match public key */
    }
    return keyring[0].PrimaryKey.KeyId == entity.PrimaryKey.KeyId, nil
}

func uint64ToBytes(i uint64) []byte {
    buf := new(bytes.Buffer)
    binary.Write(buf, binary.LittleEndian, i)
    return buf.Bytes()
}

func bytesToUint64(b []byte) uint64 {
    var i uint64
    buf := bytes.NewReader(b)
    binary.Read(buf, binary.LittleEndian, &i)
    return i
}
