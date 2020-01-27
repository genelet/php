# php
PHP version of the web development framework Genelet

# Installation
```
git clone git@github.com:genelet/php.git
```
Genelet uses "composer" to install dependencies. Go to the newly downloaded directory _php_ and run:
```
cd php
composer install
```
which will install all the dependencies.

# Tests

Assuming that "phpunit" is installed as a program, and there is database _test_ and with accessing account user *genelet_test* and blank password, run:
```
phpunit --bootstrap vendor/autoload.php tests
```
which will run all the tests in the directory _tests_. Make sure they all passed.
