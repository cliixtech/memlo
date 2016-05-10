# About Memlo

[Weed Memlo](http://38.media.tumblr.com/ebfd2b33051d202be3186ca3f565738e/tumblr_inline_mstfdikWSz1qz4rgp.png) is the cryptography library for **Cliix** products.

It provide supports for handling public/private keys, signing and hashing/digesting messages.

This project aims to provide reuse of code between backend and mobile apps.

# Building

Run ``./gradlew check`` to check code formatting and run all the tests.

In case of any **format violations**, run ``./gradlew spotlessApply`` to format the code accordingly.

To avoid getting this violation messages, you can configure eclipse to use the same formatting
rules - just point your project's java formatter use yakko.eclipseformat.xml as formatting spec
file.

## Running tests continuously

To run all tests on every change you make, use ``./gradlew -t test``
