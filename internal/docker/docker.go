package docker

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/buildpacks/pack/pkg/client"
	"github.com/buildpacks/pack/pkg/logging"
	"github.com/docker/docker/api/types"
	dockerClient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"io"
	"time"
)

// BuildRequest contains parameters for the Build command
type BuildRequest struct {
	Image      string
	WorkingDir string
	Dockerfile string
}

// Client wrapper around the docker client
type Client struct {
	docker *dockerClient.Client
	logger logging.Logger
}

type ErrorLine struct {
	Error       string      `json:"error"`
	ErrorDetail ErrorDetail `json:"errorDetail"`
}

type ErrorDetail struct {
	Message string `json:"message"`
}

func New(out io.Writer) (*Client, error) {
	buildLogger := logging.NewSimpleLogger(out)
	docker, err := dockerClient.NewClientWithOpts(
		dockerClient.FromEnv,
		dockerClient.WithVersion(client.DockerAPIVersion),
	)
	if err != nil {
		return nil, errors.Wrap(err, "creating docker client")
	}

	return &Client{
		docker: docker,
		logger: buildLogger,
	}, nil
}

// BuildAndPushImage builds and pushes an image via pack with the specified parameters in BuildRequest
func (c *Client) BuildAndPushImage(ctx context.Context, req BuildRequest) error {

	ref, err := c.parseTagReference(req.Image)
	if err != nil {
		return err
	}

	imageTag := ref.Name()

	// build docker image
	c.logger.Infof("Building image '%s' from Dockerfile '%s'", imageTag, req.Dockerfile)

	tar, err := archive.TarWithOptions(req.WorkingDir, &archive.TarOptions{})
	if err != nil {
		return err
	}

	opts := types.ImageBuildOptions{
		Dockerfile: req.Dockerfile, // "Dockerfile"
		Tags:       []string{imageTag},
		Remove:     true,
	}
	res, err := c.docker.ImageBuild(ctx, tar, opts)
	if err != nil {
		return err
	}
	lastLine := ""
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		lastLine = scanner.Text()
		c.logger.Debug(scanner.Text())
		//fmt.Println(scanner.Text())
	}

	errLine := &ErrorLine{}
	_ = json.Unmarshal([]byte(lastLine), errLine)
	if errLine.Error != "" {
		return errors.New(errLine.Error)
	}

	c.logger.Infof("Building image '%s' completed successful", imageTag)

	// push image
	c.logger.Infof("Pushing image '%s'", imageTag)

	ctxPush, cancel := context.WithTimeout(ctx, time.Second*120)
	defer cancel()

	var authConfig = types.AuthConfig{
		//	Username:      "Your Docker Hub Username",
		//	Password:      "Your Docker Hub Password or Access Token",
		//	ServerAddress: "https://index.docker.io/v1/",
	}
	// receive authConfig from cli ?

	authConfigBytes, _ := json.Marshal(authConfig)
	authConfigEncoded := base64.URLEncoding.EncodeToString(authConfigBytes)
	//c.docker.RegistryLogin()
	tag := imageTag
	optsPush := types.ImagePushOptions{RegistryAuth: authConfigEncoded}
	rd, err := c.docker.ImagePush(ctxPush, tag, optsPush)
	if err != nil {
		return err
	}

	defer rd.Close()

	err = printReader(rd)
	if err != nil {
		return err
	}

	c.logger.Infof("Pushing image '%s' completed successful", imageTag)

	return nil
}

func printReader(rd io.Reader) error {
	var lastLine string

	scanner := bufio.NewScanner(rd)
	for scanner.Scan() {
		lastLine = scanner.Text()
		fmt.Println(scanner.Text())
	}

	errLine := &ErrorLine{}
	json.Unmarshal([]byte(lastLine), errLine)
	if errLine.Error != "" {
		return errors.New(errLine.Error)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (c *Client) parseTagReference(imageName string) (name.Reference, error) {
	if imageName == "" {
		return nil, errors.New("image is a required parameter")
	}
	if _, err := name.ParseReference(imageName, name.WeakValidation); err != nil {
		return nil, err
	}
	ref, err := name.NewTag(imageName, name.WeakValidation)
	if err != nil {
		return nil, fmt.Errorf("'%s' is not a tag reference", imageName)
	}

	return ref, nil
}
