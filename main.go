package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/akerl/github-auth-lambda/auth"
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

func aclFunc(req events.Request, sess session.Session) (bool, error) {
	bucket, path, err := parseS3Params(req)
	if err != nil {
		return false, err
	}

	fullACLPath := fmt.Sprintf("%s/%s", bucket, path)
	if fullACLCheck(fullACLPath, sess) {
		return true, nil
	}
	return false, nil
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

	pc := s3Api.NewPresignClient(client)

	objReq, err := pc.PresignGetObject(context.TODO(), &s3Api.GetObjectInput{
		Bucket: &bucket,
		Key:    &path,
	}, func(opts *s3Api.PresignOptions) {
		opts.Expires = time.Duration(1 * time.Minute)
	})
	if err != nil {
		return events.Fail("Failed to load signed url")
	}
	return events.Redirect(objReq.URL, 303)
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

	githubAuth := auth.SessionCheck{
		SessionManager: *sm,
		AuthURL:        config.AuthURL,
		ACLHandler:     aclFunc,
	}

	d := mux.NewDispatcher(
		&mux.SimpleReceiver{
			HandleFunc: loadFile,
			AuthFunc:   githubAuth.AuthFunc,
		},
	)
	mux.Start(d)
}
