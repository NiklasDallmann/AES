TEMPLATE				= subdirs

SUBDIRS					= \
	lib \
	test

lib.subdir				= src/lib
test.subdir				= src/test

test.depends			= lib
