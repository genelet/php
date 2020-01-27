# php
PHP version of the web development framework Genelet

# Installation
```
git clone git@github.com:genelet/php.git
```
Genelet uses _composer_ to install dependencies. Go to the newly downloaded directory _php_ and run:
```
cd php
composer install
```
which will install all the dependencies.

# Unit Tests

Genelet uses _phpunit_ to run unit tests. Set up a database named _test_ with accessing account user *genelet_test* and blank password, run:
```
phpunit --bootstrap vendor/autoload.php tests
```
which will run all the tests in the directory _tests_. Make sure they all passed.

# Using Genelet 

Please go to the [main website](http://www.genelet.com) to learn how to use the framework.
