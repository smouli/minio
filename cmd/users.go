package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/minio/minio/pkg/auth"
)

type credPolicyInfo struct {
	secretKey string
	policy    string
}

// Credential Manager
type CredentialManager struct {
	userCredMap map[string]credPolicyInfo
}

// Get Credentials
func (cm CredentialManager) GetCredentials(accessKey string) (*auth.Credentials, bool) {

	credPolicy, ok := cm.userCredMap[accessKey]
	if !ok {
		return &auth.Credentials{}, ok
	}
	return &auth.Credentials{AccessKey: accessKey, SecretKey: credPolicy.secretKey}, ok
}

// Set Credentials
func (cm *CredentialManager) SetCredentials(cred auth.Credentials) {
	cm.userCredMap[cred.AccessKey] = credPolicyInfo{secretKey: cred.SecretKey, policy: ""}

}

type userInfoWithVersion struct {
	Version string     `json:"version"`
	Users   []userInfo `json:"users"`
}
type userInfo struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
	Policy    string `json:"policy,omitempty"`
}

// New Credential Manager
func NewCredManager() (*CredentialManager, error) {
	credMap := make(map[string]credPolicyInfo)

	//Check if file does not exist

	if _, err := os.Stat(getUsersFile()); os.IsNotExist(err) {
		// If there is no user table, return an empty cred manager
		fmt.Println("os.Stat failed")
		return &CredentialManager{}, nil
	}

	//ioutil.Readall file
	b, err := ioutil.ReadFile(getUsersFile())
	if err != nil {
		log.Fatal(err)
	}

	var u userInfoWithVersion
	//u.Users = make([]userInfo, 5)

	err = json.Unmarshal([]byte(b), &u)
	if err != nil {
		fmt.Println("Unmarshal failed")
		return &CredentialManager{}, err
	}

	// Add entries to credMap
	for _, element := range u.Users {
		credMap[element.AccessKey] = credPolicyInfo{secretKey: element.SecretKey, policy: element.Policy}

	}

	// Create a mapping of accessKey (User) to User policy.Policy
	for key, value := range credMap {
		if err := globalPolicySys.addUserPolicy(key, value.policy); err != nil {
			return &CredentialManager{}, err
		}
	}

	return &CredentialManager{userCredMap: credMap}, nil

}
