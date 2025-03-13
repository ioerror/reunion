SOURCE_DATE_EPOCH := $(shell git log -1 --pretty=%ct)
VERSION := $(shell cat src/reunion/__version__.py | cut -f 2 -d'"')
TGZ_NAME := reunion_$(VERSION).orig.tar.gz
DEB_NAME := python3-reunion_$(VERSION)-1_all.deb
DEB_BUILD_OPTIONS := nocheck

.PHONY: clean deb sdist

sdist: ./dist/$(TGZ_NAME)
./dist/$(TGZ_NAME): src/reunion
	-mkdir -p dist/source
	-mkdir -p build/tmp
	SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} flit build --format sdist
	mv dist/reunion-$(VERSION).tar.gz dist/$(TGZ_NAME)
	-ls -alh dist/$(TGZ_NAME)
	-sha256sum dist/$(TGZ_NAME)

deb: ./dist/$(DEB_NAME)

./dist/$(DEB_NAME): ./dist/$(TGZ_NAME)
	cd dist && rm -rvf "reunion-$(VERSION)" && tar xf $(TGZ_NAME) \
        && cd reunion-$(VERSION) && cp -rvp ../../debian ./debian && \
        DEB_BUILD_OPTIONS=$(DEB_BUILD_OPTIONS) dpkg-buildpackage -rfakeroot -uc -us \
	--sanitize-env && \
		cd .. && rm -rf reunion-$(VERSION)
	dpkg --contents dist/$(DEB_NAME)
	ls -alh dist/*reunion*
	sha256sum dist/$(DEB_NAME)


clean:
	-rm -rf build/ dist/ reunion.egg-info/ __pycache__/
