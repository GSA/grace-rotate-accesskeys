package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/jszwedko/go-circleci"
)

const waitTime = 10 * time.Second // 8 seconds seems to work most of the time; 7 seconds does not
const defaultFile = "testdata/credentials.json"

type creds map[string]*deployerCredential

type deployerCredential struct {
	ID       string `json:"AWS_ACCESS_KEY_ID"`
	Secret   string `json:"AWS_SECRET_ACCESS_KEY"`
	Token    string `json:"TOKEN"`
	Projects []struct {
		AwsAccessKeyID     string `json:"AWS_ACCESS_KEY_ID"`
		AwsSecretAccessKey string `json:"AWS_SECRET_ACCESS_KEY"`
		Name               string `json:"name"`
	} `json:"projects"`
	sess      *session.Session
	iamClient *iam.IAM
	stsClient *sts.STS
	alias     string
	identity  *sts.GetCallerIdentityOutput
	userName  string
}

func after(value, a string) string {
	// Get substring after a string.
	pos := strings.LastIndex(value, a)
	if pos == -1 {
		return ""
	}
	adjustedPos := pos + len(a)
	if adjustedPos >= len(value) {
		return ""
	}
	return value[adjustedPos:]
}

func parseCredentials() (*creds, error) {
	infile := defaultFile
	if len(os.Args) == 2 {
		infile = os.Args[1]
	}
	jsonFile, err := os.Open(infile)
	if err != nil {
		return nil, err
	}

	defer jsonFile.Close() // #nosec G307
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var c creds
	err = json.Unmarshal(byteValue, &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *creds) WriteFile() error {
	outfile := defaultFile
	if len(os.Args) == 2 {
		outfile = os.Args[1]
	}
	// Backup/rename infile
	err := os.Rename(outfile, outfile+".bak")
	if err != nil {
		fmt.Printf("Error creating backup of credentials file %q: %v", outfile, err)
		return err
	}

	// Write credentials
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling credentials: %v\n", err)
		return err
	}

	err = ioutil.WriteFile(outfile, b, 0600)
	if err != nil {
		fmt.Printf("Error writing credentials file %q: %v\n", outfile, err)
		return err
	}
	return nil
}

func (d *deployerCredential) checkCredential() (err error) {
	if d.sess == nil {
		fmt.Printf("Creating new session:\nID: %s\nSecret: %s\n", d.ID, d.Secret)
		d.sess, err = session.NewSession(&aws.Config{
			Region:      aws.String("us-east-1"),
			Credentials: credentials.NewStaticCredentials(d.ID, d.Secret, d.Token),
		})
		if err != nil {
			return err
		}
	}

	// IAM Alias
	if d.iamClient == nil {
		d.iamClient = iam.New(d.sess)
	}
	iamResp, err := d.iamClient.ListAccountAliases(&iam.ListAccountAliasesInput{})
	if err != nil {
		return err
	}
	d.alias = aws.StringValue(iamResp.AccountAliases[0])

	// STS Caller identity
	if d.stsClient == nil {
		d.stsClient = sts.New(d.sess)
	}
	d.identity, err = d.stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return err
	}
	d.userName = after(aws.StringValue(d.identity.Arn), "/")

	return nil
}

func (d *deployerCredential) pushToCircleCI() error {
	// Update CircleCI Environment variables
	fmt.Printf("Credential: %v\n", d)
	for _, p := range d.Projects {
		fmt.Printf("Pushing %s to %s\n", p.AwsAccessKeyID, p.Name)
		client := &circleci.Client{Token: os.Getenv("CIRCLE_TOKEN")}
		resp, err := client.AddEnvVar("GSA", p.Name, p.AwsAccessKeyID, d.ID)
		if err != nil {
			fmt.Printf("Error setting %s %s\n", p.Name, p.AwsAccessKeyID)
			return err
		}
		fmt.Printf("Resp: %v\n", resp)
		fmt.Printf("Pushing %s to %s\n", p.AwsSecretAccessKey, p.Name)
		resp, err = client.AddEnvVar("GSA", p.Name, p.AwsSecretAccessKey, d.Secret)
		if err != nil {
			fmt.Printf("Error setting %s %s\n", p.Name, p.AwsSecretAccessKey)
			return err
		}
		fmt.Printf("Resp: %v\n", resp)
	}
	return nil
}

// getIAMAdminClient ... Parse account alias to get env and determine iamAdmin role
func (d *deployerCredential) getIAMAdminClient() (iamAdminClient *iam.IAM) {
	parts := strings.Split(d.alias, "-")
	var env, roleName, roleARN string
	if len(parts) == 3 && parts[0] == "grace" && parts[2] == "management" {
		env = parts[1]
		roleName = "grace-" + env + "-operations-iamAdmin"
		roleARN = "arn:aws:iam::" + aws.StringValue(d.identity.Account) + ":role/" + roleName
		// Assume iamAdmin role
		fmt.Printf("Attempting to assume %s role\n", roleName)
		adminCreds := stscreds.NewCredentialsWithClient(d.stsClient, roleARN)
		iamAdminClient = iam.New(d.sess, &aws.Config{Credentials: adminCreds})
	} else {
		iamAdminClient = d.iamClient
	}
	return iamAdminClient
}

func (c *creds) rotateCredentials() {
	newCreds := *c
	for k, cred := range *c {
		// Check current credentials
		err := cred.checkCredential()
		if err != nil {
			fmt.Printf("Error checking credentials: %v\n", err)
			continue
		}
		if cred.alias != k {
			fmt.Printf("Alias did not match. Expected: %q Got: %q", k, cred.alias)
			continue
		}

		iamAdminClient := cred.getIAMAdminClient()

		// Create new access key
		newResp, err := iamAdminClient.CreateAccessKey(&iam.CreateAccessKeyInput{UserName: aws.String(cred.userName)})
		if err != nil {
			fmt.Printf("Error creating new access key: %v\n", err)
			continue
		}
		newCred := *cred
		newCred.ID = aws.StringValue(newResp.AccessKey.AccessKeyId)
		newCred.Secret = aws.StringValue(newResp.AccessKey.SecretAccessKey)
		fmt.Printf("export AWS_ACCESS_KEY_ID=%s && export AWS_SECRET_ACCESS_KEY=%s\n", newCred.ID, newCred.Secret)

		// Keep getting an error...maybe if I wait
		fmt.Printf("Waiting for %v\n", waitTime)
		time.Sleep(waitTime)

		err = newCred.checkCredential()
		if err != nil {
			fmt.Printf("Error checking new credentials (%s): %v\n", newCred.ID, err)
			newCred = *cred
			continue
		}
		if reflect.DeepEqual(newCred.identity, cred.identity) {
			fmt.Println("New credentials work")
		} else {
			fmt.Printf("!!!!Problem with new credentials.  Identity is different.  Expected %v\n Got: %v\n",
				cred.identity, newCred.identity)
			newCred = *cred
			continue
		}

		fmt.Println("Pushing new credentials to CircleCI")
		err = newCred.pushToCircleCI()
		if err != nil {
			fmt.Printf("Error pushing new credentials to CircleCI: %v\n", err)
			newCred = *cred
			continue
		}

		// Delete old access key
		fmt.Println("Deleting old access key")
		_, err = iamAdminClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{AccessKeyId: aws.String(cred.ID), UserName: aws.String(cred.userName)})
		if err != nil {
			fmt.Printf("Error deleting old access key: %v\n", err)
			continue
		}

		// Update credentials
		newCreds[k] = &newCred
	}

	// Write credentials
	err := newCreds.WriteFile()
	if err != nil {
		fmt.Printf("Error writing credentials file: %v\n", err)
	}
}

func main() {
	creds, err := parseCredentials()
	if err != nil {
		fmt.Printf("error parsing credentials: %v\n", err)
		return
	}
	creds.rotateCredentials()
}
