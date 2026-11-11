# Release notes

One file per version, named after its tag: `v0.1.0-alpha.2.md`. The release
workflow publishes the file as the body of the GitHub Release and adds the image
digest and chart reference underneath.

A version cannot be released without its file: the workflow stops, and a test
fails on the pull request that changes the version. Write the notes in the same
pull request, so they are reviewed with the change they describe.

Say what changed for someone running Nyctr, what they have to do, and what has
not been verified. Do not paste a commit list.
