# Contributing

Contributions are welcome! The most valuable contributions, in order of preference, are:

1. Pull requests (whether adding a feature, improving an existing feature, or fixing a bug)
1. Opening an issue (bug reports or feature requests)
1. Fork, star, watch, or share this project on your social networks.

## Pull Requests

Pull requests are definitely welcome. In order to be most useful, please try and make sure that:

* the pull request has a clear description of what it's for (new feature, enhancement, or bug fix)
* the code is clean and understandable
* the pull request would merge cleanly

### Unit Tests

If you're adding new functionality to the code base, please make sure you add a
corresponding unit test in the tests/ directory.

The project's unit tests can be run using [tox](https://tox.wiki/en/latest/).
A container to use for testing can be built using the following steps:

1. Spin up a container using ubuntu:latest: `docker run -it ubuntu:latest`
2. Add a few of prerequisite packages: `apt -y update && apt -y install git python3 tox`
3. Clone the repository: `git clone https://github.com/cevoaustralia/aws-google-auth.git`
4. Navigate to the directory and run tox: `cd aws-google-auth && tox`

Running tox without any arguments will run flake8 and the full test suite!

## Issues

Issues are also very welcome! Please try and make sure that:

* bug reports include stack traces, copied and pasted from your terminal
* feature requests include a clear description of _why_ you want that feature, not just what you want

## Thanks!

Thanks for checking out this project. While you're here, have a look at some of the other tools,
bits and pieces we've created under https://github.com/cevoaustralia
