package docker

import (
	"bufio"
	"context"
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
	"os/exec"
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
	c.logger.Infof("Building image '%s' from Dockerfile '%s'", imageTag, req.Dockerfile)
	if err := c.buildImage(ctx, req.WorkingDir, req.Dockerfile, imageTag); err != nil {
		return err
	}
	c.logger.Infof("Building image '%s' completed successful", imageTag)

	return c.pushImageExec(ctx, imageTag)
}

func (c *Client) buildImage(ctx context.Context, workingDir, dockerfile, imageTag string) error {
	tar, err := archive.TarWithOptions(workingDir, &archive.TarOptions{})
	if err != nil {
		return err
	}

	opts := types.ImageBuildOptions{
		Dockerfile: dockerfile,
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
	}

	errLine := &ErrorLine{}
	_ = json.Unmarshal([]byte(lastLine), errLine)
	if errLine.Error != "" {
		return errors.New(errLine.Error)
	}

	return nil
}

func (c *Client) pushImageExec(ctx context.Context, imageTag string) error {
	cmd := exec.CommandContext(ctx, "docker", "image", "push", imageTag)
	c.logger.Debug("Executing: " + cmd.String())
	cmd.Stdout = logging.GetWriterForLevel(c.logger, logging.DebugLevel)
	cmd.Stderr = logging.GetWriterForLevel(c.logger, logging.ErrorLevel)

	err := cmd.Run()
	if err != nil {
		c.logger.Error(err.Error())
	}

	return err
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
