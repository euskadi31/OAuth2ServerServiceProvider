# Silex OAuth2 Server Service Provider

[![Build Status](https://img.shields.io/travis/euskadi31/OAuth2ServerServiceProvider/master.svg)](https://travis-ci.org/euskadi31/OAuth2ServerServiceProvider)
[![SensioLabs Insight](https://img.shields.io/sensiolabs/i/d34991b3-bec3-4cd0-8b12-535de6569c84.svg)](https://insight.sensiolabs.com/projects/d34991b3-bec3-4cd0-8b12-535de6569c84)
[![Coveralls](https://img.shields.io/coveralls/euskadi31/OAuth2ServerServiceProvider.svg)](https://coveralls.io/github/euskadi31/OAuth2ServerServiceProvider)
[![HHVM](https://img.shields.io/hhvm/euskadi31/OAuth2ServerServiceProvider.svg)](https://travis-ci.org/euskadi31/OAuth2ServerServiceProvider)
[![Packagist](https://img.shields.io/packagist/v/euskadi31/oauth2-server-service-provider.svg)](https://packagist.org/packages/euskadi31/oauth2-server-service-provider)

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
