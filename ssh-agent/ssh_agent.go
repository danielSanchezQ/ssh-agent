package ssh_agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	bunkr_client "github.com/off-the-grid-inc/murmur/bunkr-client"
	"github.com/off-the-grid-inc/murmur/ssh-agent/storage"
)

type SSHAgent struct {
	bunkrSocketPath string
	agentSocketPath string
	bunkrClient     *bunkr_client.BunkrRPCClient
	Agent           BunkrAgent
	storage         *storage.AgentStorage
}

func NewSSHAgent(bunkrSocketPath, agentSocketPath, storagePath string) (*SSHAgent, error) {
	bunkrClient, err := bunkr_client.NewBunkrClient(bunkrSocketPath)
	if err != nil {
		return nil, err
	}
	storage, err := storage.NewBunkrStorage(storagePath)
	if err != nil {
		return nil, err
	}
	agent := &SSHAgent{
		bunkrSocketPath: bunkrSocketPath,
		agentSocketPath: agentSocketPath,
		bunkrClient:     bunkrClient,
		storage:         storage,
	}
	agent.Agent = NewKeyring(agent)
	return agent, nil
}

func (ssha *SSHAgent) Start() error {
	if err := ssha.loadKeys(); err != nil {
		return err
	}
	return nil
}

func (ssha *SSHAgent) Run() error {
	sock, err := net.Listen("unix", ssha.agentSocketPath)
	if err != nil {
		return errors.New(fmt.Sprintf("listen error: %v", err))
	}
	for {
		con, err := sock.Accept()
		if err != nil {
			log.Print(fmt.Sprintf("Accept error. Retrying in 1 second... [%v]", err))
			time.Sleep(time.Second)
			continue
		}
		go func() {
			if err := agent.ServeAgent(ssha.Agent, con); err != nil {
				// The EOF when the agent communications are shutdown makes the function
				// to return an error that we should skip
				if err != io.EOF {
					log.Print(fmt.Sprintf("ServerAgent error: %v", err))
				}
			}
		}()
	}
}

func (ssha *SSHAgent) Shutdown() {
	if err := os.Remove(ssha.agentSocketPath); err != nil {
		log.Print(fmt.Sprintf("Could not remove the agent socket file: %v", err))
	}
}

func (ssha *SSHAgent) loadKeys() error {
	bunkrSSHPubKeysData, err := ssha.ListPubKeys()
	if err != nil {
		return errors.New(fmt.Sprintf("Error retrieving public keys: %v", err))
	}

	for _, secretInfo := range bunkrSSHPubKeysData {
		err = ssha.AddKey(secretInfo)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ssha *SSHAgent) ListPubKeys() ([]*storage.Secret, error) {
	if err := ssha.storage.ReloadStorageData(); err != nil {
		return nil, err
	}
	secrets, err := ssha.storage.GetSecrets()
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func (ssha *SSHAgent) AddKey(secret *storage.Secret) error {
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey(secret.PublicData)
	if err != nil {
		log.Print(err)
		return err
	}
	groupName := ""
	if secret.Group != nil {
		groupName = secret.Group.Name
	}
	signer, err := NewSignerFromBunkr(sshPub, ssha.bunkrClient, secret.Name, groupName)
	if err != nil {
		log.Print(err)
		return err
	}
	key := BunkrAddedKey{
		// PrivateKey must be a *rsa.PrivateKey, *dsa.PrivateKey or
		// *ecdsa.PrivateKey, which will be inserted into the agent.
		Signer: signer,
		// Comment is an optional, free-form string.
		Comment: "hmm",
		// LifetimeSecs, if not zero, is the number of seconds that the
		// agent will store the key for.
		LifetimeSecs: 0,
		// ConfirmBeforeUse, if true, requests that the agent confirm with the
		// user before each use of this key.
		ConfirmBeforeUse: false,
	}

	if err = ssha.Agent.AddFromBunkr(key); err != nil {
		log.Print(err)
		return err
	}
	return nil
}

func (ssha *SSHAgent) ImportKey(secretName string) error {
	secretData, err := ssha.bunkrClient.ExportPublicData(secretName)
	if err != nil {
		return err
	}

	byteContent, err := base64.StdEncoding.DecodeString(secretData)
	if err != nil {
		return err
	}

	var secret storage.Secret
	if err := json.NewDecoder(bytes.NewReader(byteContent)).Decode(&secret); err != nil {
		return err
	}

	unmarshalPubKeyData := func(b []byte) (*ecdsa.PublicKey, error) {
		pk := new(ecdsa.PublicKey)
		var res [][]byte
		if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&res); err != nil {
			return nil, err
		}

		if err := pk.X.UnmarshalText(res[0]); err != nil {
			return nil, err
		}
		if err := pk.Y.UnmarshalText(res[1]); err != nil {
			return nil, err
		}
		pk.Curve = elliptic.P256()
		return pk, nil
	}
	bunkrPubKey, err := unmarshalPubKeyData(secret.PublicData)
	if err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(bunkrPubKey)
	if err != nil {
		return err
	}
	secret.PublicData = ssh.MarshalAuthorizedKey(sshPub)

	if err := ssha.storage.StoreSecret(&secret); err != nil {
		return err
	}

	if err := ssha.AddKey(&secret); err != nil {
		return err
	}

	return nil
}
