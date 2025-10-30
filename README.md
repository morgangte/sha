# Secure Hash Algorithms

This is a C implementation of the following Secure Hash Algorithms:
- SHA-1
- SHA-256

### Secure Hash Algorithms

The Secure Hash Algorithms are a family of cryptographic hash functions published by the National Institute of Standards and Technology (NIST) as a U.S. Federal Information Processing Standard (FIPS).

This implementation directly follows the standard available at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf.

### Quick start

Once in the project folder, compile and run tests with:

```
$ make
$ make run
```

### Dependencies

```
$ apt install build-essential
```

And if you wish to generate the documentation:

```
$ apt install doxygen
```

### Documentation

Documentation is available online at https://morgangte.github.io/sha-256/.

#### Locally

Please first check dependencies. Then, generate the documentation with:

```
$ make docs
```

Access it via any browser, e.g. with Firefox:

```
$ firefox docs/html/index.html
```

### License

[MIT](https://choosealicense.com/licenses/mit/)

Source code is available at https://github.com/morgangte/sha-256.

### Author

Morgan Gillette
