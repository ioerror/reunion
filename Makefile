PKG_NAME := rendez
SOURCE_DATE_EPOCH := $(shell git log -1 --pretty=%ct)
VERSION := $(shell cat src/$(PKG_NAME)/__version__.py | cut -f 2 -d'"')
TGZ_NAME := $(PKG_NAME)_$(VERSION).orig.tar.gz
DEB_VERSION := 1
DEB_NAME := python3-$(PKG_NAME)_$(VERSION)-$(DEB_VERSION)_all.deb
DEB_BUILD_OPTIONS := check

.PHONY: clean deb sdist

sdist: ./dist/$(TGZ_NAME)
./dist/$(TGZ_NAME): src/$(PKG_NAME)
	-mkdir -p dist/source
	-mkdir -p build/tmp
	SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} flit build --format sdist
	mv dist/$(PKG_NAME)-$(VERSION).tar.gz dist/$(TGZ_NAME)
	-ls -alh dist/$(TGZ_NAME)
	-sha256sum dist/$(TGZ_NAME)

deb: ./dist/$(DEB_NAME)

./dist/$(DEB_NAME): ./dist/$(TGZ_NAME)
	cd dist && rm -rvf "$(PKG_NAME)-$(VERSION)" && tar xf $(TGZ_NAME) \
        && cd $(PKG_NAME)-$(VERSION) && cp -rvp ../../debian ./debian && \
        DEB_BUILD_OPTIONS=$(DEB_BUILD_OPTIONS) dpkg-buildpackage -rfakeroot -uc -us \
	--sanitize-env && \
		cd .. && rm -rf $(PKG_NAME)-$(VERSION)
	dpkg --contents dist/$(DEB_NAME)
	ls -alh dist/*$(PKG_NAME)*
	sha256sum dist/$(DEB_NAME)

pypi-check:
	cp dist/*$(VERSION)*.orig.tar.gz dist/rendez-$(VERSION).tar.gz
	python3 -m twine check dist/rendez-$(VERSION).tar.gz

pypi-upload: pypi-check
	python3 -m twine upload --repository pypi dist/rendez-$(VERSION).tar.gz

clean:
	-rm -rf build/ dist/ $(PKG_NAME).egg-info/
	-rm -rf __pycache__/
	-rm -rf test/__pycache__
	-rm -rf src/$(PKG_NAME)/__pycache__
	-rm -rf src/$(PKG_NAME)/vous/__pycache__
	-rm -rf src/$(PKG_NAME)/vous/reunion/__pycache__
