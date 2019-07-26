# Spring Boot MITREid Connect
---

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/net.simpledynamics/openid-connect-server-spring-boot-config/badge.svg)](https://maven-badges.herokuapp.com/maven-central/net.simpledynamics/openid-connect-server-spring-boot-config) [![Travis CI](https://travis-ci.org/simpledynamics/openid-connect-server-spring-boot.svg?branch=master)](https://travis-ci.org/simpledynamics/openid-connect-server-spring-boot)

A Spring Boot Configuration for the [MITREid OpenID Connect Server](https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server). 

This project separates the OpenID Connect Server [configuration](openid-connect-server-spring-boot-config) from the [UI](openid-connect-server-spring-boot-ui-thymeleaf), and includes [sample applications](samples). 

The [default](samples/default) sample application attempts to be as close as possible to the [maven overlay web application](https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server/tree/master/openid-connect-server-webapp) from MITREid, while other samples give examples of how to customize the OpenID Connect server to fit your needs.

Pull requests and feature improvements are welcome.

Currently supports Spring Boot 1.5.21, MitreId Connect 1.3.3, and Spring Security 4.3.22

## Password Encoders

The possibility of using a different password encoders for users and clients has been added through configuration. From now on you can configure MIDTREID Connect with some of the four types of encoders that come out-of-the-box in Spring.

To configure a different encoder type (the default encoder NoOpPasswordEncoder), the following configuration must be added to the yml file:

```yaml
openid:
  connect:
    crypto:
      password-encoder:
        clients:
          bcrypt:
            enabled: true
            strength: -1
        users:
          bcrypt: 
            enabled: true
            strength: -1    `
```            
            
openid.connect.crypto.password-encoder.clients defines the password encoder for clients and in openid.crypto.password-encoder.users for users.            

The configuration of the different types of encoders is shown below.          

### BCrypt Password Encoder
To configure a BCrypt password encoder you will need to add the bcrypt property with the following properties:

 * enabled: enables (true) or disables (false) the encoder
 * strength: the log rounds to use, between 4 and 31

```yaml
openid:
  connect:
    crypto:
      password-encoder:
        clients:
          bcrypt:
            enabled: true
            strength: -1
        users:
          bcrypt: 
            enabled: true
            strength: -1   
```  

### SCrypt Password Encoder
To configure a SCrypt password encoder you will need to add the scrypt property with the following properties:

 * enabled: enables (true) or disables (false) the encoder
 * cpu-cost: cpu cost of the algorithm (as defined in scrypt this is N).  must be power of 2 greater than 1. Default is currently 16,348 or 2^14)
 * memory-cost: memory cost of the algorithm (as defined in scrypt this is r) Default is currently 8.
 * parallelization: the parallelization of the algorithm (as defined in scrypt this is p) Default is currently 1. Note that the implementation does not currently take advantage of parallelization.
 * key-length: key length for the algorithm (as defined in scrypt this is dkLen). The default is currently 32.
 * salt-length: salt length (as defined in scrypt this is the length of S). The default is currently 64.

```yaml
openid:
  connect:
    crypto:
      password-encoder:
        clients:
          scrypt:
            enabled: true
            cpu-cost: 16384
            memory-cost: 8
            parallelization: 1
            key-length: 32
            salt-length: 64
        users:
          scrypt: 
            enabled: true
            cpu-cost: 16384
            memory-cost: 8
            parallelization: 1
            key-length: 32
            salt-length: 64 
```  

### Standard Password Encoder
To configure a Standard password encoder you will need to add the standard property with the following properties:

 * enabled: enables (true) or disables (false) the encoder
 * secret: the secret key used in the encoding process (should not be shared). Default ""

```yaml
openid:
  connect:
    crypto:
      password-encoder:
        clients:
          standard:
            enabled: true
            secret: a_secret_word
        users:
          standard: 
            enabled: true
            secret: a_secret_word     
```            
### Pbkdf2 Password Encoder
To configure a Pbkdf2 password encoder you will need to add the pbkdf2 property with the following properties:

 * enabled: enables (true) or disables (false) the encoder
 * secret: the secret key used in the encoding process (should not be shared)

```yaml
openid:
  connect:
    crypto:
      password-encoder:
        clients:
          pbkdf2:
            enabled: true
            secret: a_secret_word
        users:
          pbkdf2: 
            enabled: true
            secret: a_secret_word
```                      