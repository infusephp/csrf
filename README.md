csrf
====

[![Build Status](https://travis-ci.org/infusephp/csrf.svg?branch=master&style=flat)](https://travis-ci.org/infusephp/csrf)
[![Coverage Status](https://coveralls.io/repos/infusephp/csrf/badge.svg?style=flat)](https://coveralls.io/r/infusephp/csrf)
[![Latest Stable Version](https://poser.pugx.org/infuse/csrf/v/stable.svg?style=flat)](https://packagist.org/packages/infuse/csrf)
[![Total Downloads](https://poser.pugx.org/infuse/csrf/downloads.svg?style=flat)](https://packagist.org/packages/infuse/csrf)
[![HHVM Status](http://hhvm.h4cc.de/badge/infuse/csrf.svg?style=flat)](http://hhvm.h4cc.de/package/infuse/csrf)

CSRF protection for Infuse Framework. Built on [symfony/security-csrf](https://github.com/symfony/security-csrf/).

## Installation

1. Install the package with [composer](http://getcomposer.org):

   ```
   composer require infuse/csrf
   ```

2. Add the services in your app's configuration:
   
   ```php
   'services' => [
      // ...
      'csrf' => 'Infuse\Csrf\Csrf',
      'csrf_tokens' => 'Infuse\Csrf\CsrfTokens',
      // ...
   ]
   ```

3. Add the middleware to your app:

   ```php
   $app->middleware($app['csrf']);
   ```

## Usage

Any POST, PUT, PATCH, and DELETE request that has the middleware installed will check for a valid CSRF token. With a line of code you can add CSRF tokens to a form (Smarty example):

```html
<form action="/transfer" method="POST">
   {$app.csrf->render($req) nofilter}
   <!-- rest of your form... -->
</form>
```