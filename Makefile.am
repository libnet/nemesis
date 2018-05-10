ACLOCAL_AMFLAGS  = -I m4
AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS          = src man
doc_DATA         = ChangeLog.md README.md docs/CREDITS LICENSE
EXTRA_DIST       = ChangeLog.md README.md docs/CREDITS LICENSE makefile.win
DISTCLEANFILES   = *~ DEADJOE semantic.cache *.gdb *.elf core core.* *.d

MD5 = md5sum
md5-dist:
	@for file in $(DIST_ARCHIVES); do	\
		$(MD5) $$file > $$file.md5;	\
	done

## Check if tagged in git
release-hook:
	if [ ! `git tag | grep $(PACKAGE_VERSION)` ]; then				\
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

## Target to run when building a release
## distcheck <-- does not work atm., wrong search path for source/header files
release: distcheck release-hook md5-dist
	@echo
	@echo "Resulting release files:"
	@echo "================================================================="
	@for file in $(DIST_ARCHIVES); do						\
		printf "$$file    \tDistribution tarball\n";				\
		printf "$$file.md5\t"; cat ../$$file.md5 | cut -f1 -d' ';		\
		mv $$file $$file.md5 ../;						\
	done
