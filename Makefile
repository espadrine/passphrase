SHELL = /bin/bash

browser.js: main.js
	words="$$(echo 'var words = ['; <words-en sed 's/^/"/; s/$$/",/'; echo '];')"; \
	sed <main.js '/INSERT_WORDS_HERE/ {r '<(echo "$$words")$$'\n''d}' >browser.js
