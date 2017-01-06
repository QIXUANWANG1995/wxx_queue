SHELL := /bin/bash

MODULENAME := sch_wxx

module:
		-@mkdir build
		@cp -Rf kmod build
		@cp -Rf include build
		@cd build/kmod; make all;

module_install:
		make module;
		@cd build/kmod; sudo insmod $(MODULENAME).ko

module_remove:
		sudo rmmod $(MODULENAME)

clean:
		-@rm -rf build

module_tags:
	ctags -R --c++-kinds=+p --fields=+iaS --extra=+q /lib/modules/$(shell uname -r)/build/include
