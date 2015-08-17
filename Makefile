composer.phar:
	@curl -sS https://getcomposer.org/installer | php

vendor: composer.phar
	@php composer.phar install

test: vendor
	@phpunit --coverage-text --coverage-html build/coverage

check: vendor
	@./vendor/bin/phpcs --standard=./vendor/leaphub/phpcs-symfony2-standard/leaphub/phpcs/Symfony2/ ./src

phpmd: vendor
	@./vendor/bin/phpmd ./src/ text unusedcode

travis: test check
