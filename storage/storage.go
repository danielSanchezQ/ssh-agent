package storage

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

type AgentStorage struct {
	data        *AgentData
	storagePath string
}

type AgentData struct {
	Secrets map[string]*SecretData
}

type SecretData struct {
	FileId     string
	CapId      string
	SecretType string
	PublicData string
	Group      string
}

func NewBunkrStorage(path string) (*AgentStorage, error) {
	var bunkrData AgentData
	if _, err := os.Stat(path); os.IsNotExist(err) {
		bunkrData = AgentData{
			Secrets: make(map[string]*SecretData),
		}
	} else {
		b, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &bunkrData); err != nil {
			return nil, err
		}
	}

	return &AgentStorage{
		data:        &bunkrData,
		storagePath: path,
	}, nil
}

func (storage *AgentStorage) ReloadStorageData() error {
	var bunkrData AgentData
	b, err := ioutil.ReadFile(storage.storagePath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &bunkrData); err != nil {
		return err
	}
	storage.data = &bunkrData
	return nil
}

func (storage *AgentStorage) GetSecrets() ([]*Secret, error) {
	secrets := make([]*Secret, len(storage.data.Secrets))
	i := 0
	for k, v := range storage.data.Secrets {
		s, err := storage.decodeSecret(k, v)
		if err != nil {
			return nil, err
		}
		secrets[i] = s
		i++
	}
	return secrets, nil
}

func (storage *AgentStorage) StoreSecret(secret *Secret) error {
	if _, ok := storage.data.Secrets[secret.Name]; ok {
		return errors.New(fmt.Sprintf("Secret with name %s already exists, please chose a different name", secret.Name))
	}
	secretData, err := storage.encodeSecret(secret)
	if err != nil {
		return err
	}
	storage.data.Secrets[secret.Name] = secretData
	if err := storage.Dump(); err != nil {
		return err
	}

	return nil
}

func (storage *AgentStorage) RemoveSecret(name string) error {
	delete(storage.data.Secrets, name)
	if err := storage.Dump(); err != nil {
		return err
	}
	for k, v := range storage.data.Secrets {
		if v.Group == name {
			if err := storage.RemoveSecret(k); err != nil {
				return err
			}
		}
	}

	return nil
}

func (storage *AgentStorage) GetSecret(name string) (*Secret, error) {
	secretData, ok := storage.data.Secrets[name]
	if !ok {
		return nil, errors.New(fmt.Sprintf("No secret exists with name: %s", name))
	}

	return storage.decodeSecret(name, secretData)
}

func (storage *AgentStorage) SecretExists(name string) bool {
	_, ok := storage.data.Secrets[name]
	return ok
}

func (storage *AgentStorage) GetSecretsByType(secretType string) ([]*Secret, error) {
	allSecrets, err := storage.GetSecrets()
	if err != nil {
		return nil, err
	}
	secrets := make([]*Secret, 0)
	for _, secret := range allSecrets {
		if string(secret.SecretType) == secretType {
			secrets = append(secrets, secret)
		}
	}

	return secrets, nil
}

func (storage *AgentStorage) Dump() error {
	data, err := json.Marshal(storage.data)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(storage.storagePath, data, 0755); err != nil {
		return err
	}

	return nil
}

func (storage *AgentStorage) decodeSecret(name string, secretData *SecretData) (*Secret, error) {
	data, err := base64.StdEncoding.DecodeString(secretData.PublicData)
	if err != nil {
		return nil, err
	}
	s := &Secret{
		Name:       name,
		FileId:     secretData.FileId,
		CapId:      secretData.CapId,
		SecretType: secretData.SecretType,
		PublicData: data,
		Group:      nil,
	}
	if secretData.Group != "" {
		group, err := storage.decodeSecret(secretData.Group, storage.data.Secrets[secretData.Group])
		if err != nil {
			return nil, err
		}
		s.Group = group
	}
	return s, nil
}

func (storage *AgentStorage) encodeSecret(secret *Secret) (*SecretData, error) {
	sd := &SecretData{
		FileId:     secret.FileId,
		CapId:      secret.CapId,
		SecretType: string(secret.SecretType),
		PublicData: base64.StdEncoding.EncodeToString(secret.PublicData),
		Group:      "",
	}
	if secret.Group != nil {
		sd.Group = secret.Group.Name
	}

	return sd, nil
}
