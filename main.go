package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/akerl/github-auth-lambda/session"
	"github.com/akerl/go-lambda/apigw/events"
	"github.com/akerl/go-lambda/mux"
	"github.com/akerl/go-lambda/s3"
	s3Api "github.com/aws/aws-sdk-go-v2/service/s3"
)

var sm *session.Manager

func parseS3Params(req events.Request) (string, string, error) {
	params := events.Params{Request: &req}
	bucket := params.Lookup("bucket")
	path := params.Lookup("path")

	if bucket == "" || path == "" {
		return "", "", fmt.Errorf("settings not provided")
	}
	fmt.Printf("Parsed bucket and path: %s/%s\n", bucket, path)
	return bucket, path, nil
}

func fullACLCheck(aclName string, sess session.Session) bool {
	parts := strings.Split(aclName, "/")

	for i := len(parts); i > 0; i-- {
		chunk := strings.Join(parts[:i], "/")
		if allowed, found := aclCheck(chunk, sess); found {
			return allowed
		}
	}

	allowed, _ := aclCheck("default", sess)
	return allowed
}

func aclCheck(aclName string, sess session.Session) (bool, bool) {
	fmt.Printf("Checking ACLs: %s\n", aclName)
	acl, ok := config.ACLs[aclName]
	if !ok {
		return false, false
	}

	for _, aclEntry := range acl {
		if aclEntry == "anonymous" {
			return true, true
		}
		aclSlice := strings.SplitN(aclEntry, "/", 2)
		userOrgTeams, ok := sess.Memberships[aclSlice[0]]
		if ok {
			if len(aclSlice) == 1 {
				return true, true
			}
			for _, userTeam := range userOrgTeams {
				if userTeam == aclSlice[1] {
					return true, true
				}
			}
		}
	}
	return false, true
}

func authFunc(req events.Request) (events.Response, error) {
	bucket, path, err := parseS3Params(req)
	if err != nil {
		return events.Fail("failed to authenticate request")
	}

	sess, err := sm.Read(req)
	if err != nil {
		return events.Fail("failed to authenticate request")
	}

	if sess.Login == "" {
		authURL, err := url.Parse(config.AuthURL)
		if err != nil {
			return events.Response{}, err
		}

		returnURL := url.URL{
			Host:   req.Headers["Host"],
			Path:   req.Path,
			Scheme: "https",
		}
		returnValues := authURL.Query()
		returnValues.Set("redirect", returnURL.String())
		authURL.RawQuery = returnValues.Encode()

		return events.Redirect(authURL.String(), 303)
	}

	fullACLPath := fmt.Sprintf("%s/%s", bucket, path)
	if fullACLCheck(fullACLPath, sess) {
		return events.Response{}, nil
	}

	return events.Reject("Not authorized")
}

func loadFile(req events.Request) (events.Response, error) {
	bucket, path, err := parseS3Params(req)
	if err != nil {
		return events.Fail("Failed to load S3 path")
	}

	client, err := s3.Client()
	if err != nil {
		return events.Fail("Failed to load S3 connection")
	}

	objReq := client.GetObjectRequest(&s3Api.GetObjectInput{
		Bucket: &bucket,
		Key:    &path,
	})
	url, err := objReq.Presign(1 * time.Minute)
	if err != nil {
		return events.Fail("Failed to load signed url")
	}
	return events.Redirect(url, 303)
}

func main() {
	var err error
	config, err = loadConfig()
	if err != nil {
		panic(err)
	}

	sm = &session.Manager{
		Name:     "session",
		SignKey:  config.SignKey,
		EncKey:   config.EncKey,
		Lifetime: config.Lifetime,
		Domain:   config.Domain,
	}

	d := mux.NewDispatcher(
		&mux.SimpleReceiver{
			HandleFunc: loadFile,
			AuthFunc:   authFunc,
		},
	)
	mux.Start(d)
}
