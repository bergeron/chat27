/* test.go */

package main
import (
	"testing"
	"os"
	"fmt"
	"log"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"github.com/boltdb/bolt"
)

var testDB *bolt.DB

func TestMain(m *testing.M) { 
    setup()
	result := m.Run()
    teardown()
    os.Exit(result)
}

func setup(){
	var err error
	testDB, err = bolt.Open("chat27_test.db", 0600, nil)
    if err != nil {
        log.Fatal(err)
    }
    defer testDB.Close()

	testDB.Update(func(tx *bolt.Tx) error {
		tx.DeleteBucket([]byte("fingerprints"))
		tx.DeleteBucket([]byte("messages"))
		
		tx.CreateBucket([]byte("fingerprints"))
		tx.CreateBucket([]byte("messages"))
		return nil
	})
}

func teardown(){
	testDB.Update(func(tx *bolt.Tx) error {
 		tx.DeleteBucket([]byte("fingerprints"))
		tx.DeleteBucket([]byte("messages"))
		return nil
	})
}

func TestRegisterSamePubKeyTwice(t *testing.T) {

}
