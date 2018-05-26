[![Build Status](https://travis-ci.org/andreacomo/keytool-helper.svg?branch=master)](https://travis-ci.org/andreacomo/keytool-helper)

# KeyTool Utility Project

This project try to simplify common operation with KeyTools such as:

* generate a **new key pair** with **self-signed certificate**
* add an **existing private key and certificate**
* generate a new *Certificate Sign Request* (**CSR**)
* sign a CSR and produce a **certification chain** (p7b)

##### Disclaimer:
In order to reduce dependencies, some classes of `sun.security` package has been used: 
may not compile on JDKs different than OpenJDK/Oracle.

## How to use

Code is better than thousand words: check out [`KeyToolsTest`](https://github.com/andreacomo/keytool-helper/blob/master/src/test/java/it/codingjam/keytool/services/KeyToolsTest.java)!
