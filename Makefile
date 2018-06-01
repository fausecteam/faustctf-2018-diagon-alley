SERVICE := diagon_alley
DESTDIR ?= dist_root
SERVICEDIR ?= /srv/$(SERVICE)
USER ?= diagon_alley

.PHONY: build install clean

build: com frontend shops

com:
	$(MAKE) -C src/com

frontend:
	$(MAKE) -C src/frontend

shops:
	$(MAKE) -C src/shops



install: build
	mkdir -p $(DESTDIR)$(SERVICEDIR)
	mkdir -p $(DESTDIR)$(SERVICEDIR)/data
	#install -m 700 -o $(USER) -d $(DESTDIR)$(SERVICEDIR)/data 
	cp src/frontend/diagon_alley $(DESTDIR)$(SERVICEDIR)/
	cp src/shops/shops $(DESTDIR)$(SERVICEDIR)/
	mkdir -p $(DESTDIR)/etc/systemd/system
	cp src/frontend/diagon_alley@.service $(DESTDIR)/etc/systemd/system/
	cp src/frontend/diagon_alley.socket $(DESTDIR)/etc/systemd/system/

clean:
	$(MAKE) -C src/com clean
	$(MAKE) -C src/frontend clean
	$(MAKE) -C src/shops clean
