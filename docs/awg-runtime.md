# AWG runtime

BPC v0.2.0 intentionally pins the official AmneziaWG userspace container to the AWG 2.0.0 amd64 image and digest used by the deployment script. This keeps the first interoperability milestone stable while upstream AWG 3.x evolves independently.

The pin is part of the deployment contract and is covered by tests. Changing it requires an explicit BPC release and a new end-to-end transport test.
