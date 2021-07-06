SUBDIRS          = src man
doc_DATA         = ChangeLog.md README.md docs/CREDITS LICENSE
EXTRA_DIST       = ChangeLog.md README.md docs/CREDITS LICENSE makefile.win
DISTCLEANFILES   = *~ DEADJOE semantic.cache *.gdb *.elf core core.* *.d

## Generate .deb package
package:
	@debuild -uc -us -B --lintian-opts --profile debian -i -I --show-overrides

## Generate checksum files, works now but may b0rk "make check" when we add unit tests
distcheck-hook:
	@for file in $(DIST_ARCHIVES); do						\
		md5sum    $$file > $(top_srcdir)/../$$file.md5;				\
		sha256sum $$file > $(top_srcdir)/../$$file.sha256;			\
		ln $$file $(top_srcdir)/../;						\
	done

## Check if tagged in git
release-hook:
	if [ ! `git tag v$(PACKAGE_VERSION) | grep v$(PACKAGE_VERSION)` ]; then		\
		echo;									\
		printf "\e[1m\e[41mCannot find release tag $(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[5mDo release anyway?\e[0m "; read yorn;			\
		if [ "$$yorn" != "y" -a "$$yorn" != "Y" ]; then				\
			printf "OK, aborting release.\n";				\
			exit 1;								\
		fi;									\
		echo;									\
	else										\
		echo;									\
		printf "\e[1m\e[42mFound GIT release tag $(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[44m>>Remember to push tags!\e[0m\n";			\
		echo;									\
	fi

## Target to run when building a release manually
release: release-hook distcheck package
	@echo
	@echo "Resulting release files in parent dir:"
	@echo "=================================================================================================="
	@for file in $(DIST_ARCHIVES); do						\
		printf "%-32s Distribution tarball\n" $$file;				\
		printf "%-32s " $$file.md5;    cat ../$$file.md5    | cut -f1 -d' ';	\
		printf "%-32s " $$file.sha256; cat ../$$file.sha256 | cut -f1 -d' ';	\
	done
	@for file in `cd ..; ls nemesis_$(VERSION)* $(PACKAGE)-dbg*_$(VERSION)*`; do	\
		printf "%-32s Debian/Ubuntu package\n" $$file;				\
	done
