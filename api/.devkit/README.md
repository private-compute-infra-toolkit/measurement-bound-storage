# DevKit

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/private-compute-infra-toolkit/devkit/badge)](https://scorecard.dev/viewer/?uri=github.com/private-compute-infra-toolkit/devkit)

## What is DevKit?

DevKit is a toolkit for bootstrapping and managing software projects. It provides a set of templates
and tools to help you get started with a new project quickly and easily, while also providing a
consistent structure and set of best practices.

## Prerequisites

Before you can use DevKit, you will need to have the following tools installed:

-   Sudo-less [Docker](https://www.docker.com/)
-   [Docker Buildx plugin](https://github.com/docker/buildx)
-   [Bazelisk](https://github.com/bazelbuild/bazelisk/releases) (optional, if you want to build code
    outside of DevKit)

## Getting Started

### Bootstrapping a New Project

To start a new project using a DevKit template, follow these steps:

1.  Create a directory for your new project and navigate into it:

    ```bash
    mkdir my-new-project
    cd my-new-project
    ```

1.  Add DevKit to your project.

    For local testing, you can create a symbolic link to your DevKit clone:

    ```bash
    ln -s /your/path/to/devkit/devkit .devkit
    ```

    For a proper project setup, it is recommended to add DevKit as a Git submodule. This will ensure
    that your project is tied to a specific version of DevKit, making it easier to maintain and
    update.

    ```bash
    git submodule add sso://privacysandbox/hit/devkit .devkit
    ```

    Expose the directory with entrypoint scripts:

    ```bash
    ln -s .devkit/devkit devkit
    ```

1.  Run the bootstrap script with your desired template. The bootstrap script will populate your
    current directory with the files from the chosen template, ready for you to start developing.

    ```bash
    devkit/bootstrap --template <template> --args [key=value ...]
    ```

    For example, to bootstrap a C++ project with the `llvm_custom_sysroot` toolchain:

    ```bash
    devkit/bootstrap --template cpp --args toolchain=llvm_custom_sysroot
    ```

    A full list of supported templates and their parameters can be found in the `templates.txt`
    file.

This populates your current directory with the files from the chosen template, ready for you to
start developing.

## Configuration

The project configuration is stored in `devkit.json`. See [docs/devkit_json.md](docs/devkit_json.md)
for details.

## Local Development

### Running CI jobs locally

You can run the Continuous Integration (CI) jobs locally to validate your changes before pushing
them. This is as simple as executing the `tools/ci/*` scripts directly.

For the `Build-AMD64` job:

```bash
tools/ci/build
```

To keep the workspace for debugging purposes, run the script with the `--debug` flag:

```bash
tools/ci/build --debug
```

After the job is executed, you can find its workspace in `/tmp/workspace`. The `/tmp/workspace`
directory is removed when any new `build*` script with the `--debug` flag is executed.

To run other variants of the build, like e.g.: `Build-RockyLinux-AMD64`, execute the corresponding
script:

```bash
tools/ci/build-rockylinux
```

To execute the `Pre-Commit` job:

```bash
tools/ci/pre-commit
```

The `tools/ci/pre-commit` also accepts a `--debug` flag.

### Working with Build Images

Build images are Docker images that contain all the necessary dependencies and tools to build your
project. They provide a consistent and reproducible build environment.

To start the default build image:

```bash
devkit/build
```

To start other variants, use the corresponding `devkit/build-<variant>` script. Supported variants
include `debian` and `rockylinux`.

```bash
devkit/build-debian
```

### Working with Docker Images

This section provides more details on how to work with the Docker images used by DevKit.

#### Debugging builds

To build and push all the images:

```bash
cd devkit/
scripts/docker/build.py --search-path images/ --config devkit.json
```

You can modify any of the Dockerfiles to trigger a new build.

To build a specific image:

```bash
scripts/docker/build.py build-env --search-path images/ --config devkit.json
```

And finally, an example of a command with all the options used:

```bash
scripts/docker/build.py build-env --search-path images/ --log-file /dev/null --config devkit.json --print-tag
```

This is how DevKit gets the tag of the image on which to execute a command.

#### Updating dependencies

A `Dockerfile` in the `images/` directory usually has a list of package versions specified at the
beginning:

```dockerfile
ARG BAR_BAZ_VERSION=2.0.*
ARG FOO_VERSION=1.0.0-*
```

The versions are then used in the `apt-get install` command (or equivalent):

```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bar-baz=${BAR_BAZ_VERSION} \
      foo=${FOO_VERSION} \
 && rm -rf /var/lib/apt/lists/*
```

To update these dependencies, follow these steps:

1.  Temporarily replace the versions with wildcards in the `Dockerfile`:

    ```dockerfile
    ARG BAR_BAZ_VERSION=*
    ARG FOO_VERSION=*
    ```

1.  Build the image. This will pull the latest versions of the packages.

1.  After the image is built, run it and list the versions of the installed packages:

    ```bash
    apt list --installed
    ```

    You can also grep for a specific package:

    ```bash
    apt list --installed | grep foo
    ```

1.  Finally, replace the wildcards in the `Dockerfile` with the actual new versions.

Be careful not to overpin dependencies. A valid update would be, for example, from `1.0.0-*` to
`1.0.2-*`. A problematic one would be if the wildcard is dropped, e.g., from `1.0.0-*` to
`1.0.1-patch2`. If `patch2` is later replaced by `patch3`, the build will fail.

## Contributing

Contributions are welcome! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for more
information.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
