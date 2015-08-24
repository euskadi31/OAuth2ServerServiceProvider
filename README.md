# Silex OAuth2 Server Service Provider

[![Build Status](https://travis-ci.org/euskadi31/OAuth2ServerServiceProvider.svg?branch=master)](https://travis-ci.org/euskadi31/OAuth2ServerServiceProvider)
[![SensioLabsInsight](https://insight.sensiolabs.com/projects/060794b2-c8f1-4713-81fa-4aa29494e111/mini.png)](https://insight.sensiolabs.com/projects/060794b2-c8f1-4713-81fa-4aa29494e111)
[![Coverage Status](https://coveralls.io/repos/euskadi31/OAuth2ServerServiceProvider/badge.svg?branch=master&service=github)](https://coveralls.io/github/euskadi31/OAuth2ServerServiceProvider?branch=master)

## Install

Add `euskadi31/oauth2-server-service-provider` to your `composer.json`:

    % php composer.phar require euskadi31/oauth2-server-service-provider:~1.0

## Usage

### Configuration

```php
<?php

$app = new Silex\Application;

$app->register(new \Euskadi31\Silex\Provider\OAuth2ServerServiceProvider);
```

## License

OAuth2ServerServiceProvider is licensed under [the MIT license](LICENSE.md).
