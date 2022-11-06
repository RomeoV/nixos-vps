{ config, pkgs, ...}: {
  imports = [
    ./hardware-configuration.nix
  ];

  programs = {
    mosh.enable = true;
    git.enable = true;
    neovim = {
      enable = true;
      defaultEditor = true;
      withPython3 = false;
      withRuby = false;
    };
  };

  boot.cleanTmpDir = true;
  zramSwap.enable = true;

  networking.hostName = "mycloud-nixos";
  services.openssh.enable = true;
  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIzDCdxCAPnbdzwkKpp/9AUGMyABSPj/vZffRQoojdHh6Ct+9fZ60vYOS9NaQy9bqdagC0bHrrBvELiTqbAj5E3I1E7Mfp2BXjI/ig+NTlp0SIoaXnlLRNxnb+TSEDuAdqMdgwjxuy63T5PK04e7AH24NQ8J9sF16QAu0A0VurZEzPTLVZIoFCr/qmxZLnsJELdAtmnxCf+ZlBSs+v0qWOibOQ1mgKecii+0hRPSDpmY62FI++AzNoeVJ4j0ObSC/hpLMYkF5DJSkwaD+4+7CDLFhHdIQ5AzZNZp4gS2IESGUVTbUhXHm0YOr/xj66ZLqDzA16F+dSkKrnfRyTGrjdeWNsMTy42W42wEK1FhbHfsg4AQtT7S3kyiKS0lUFPdH34Q6iiTShTtySDCPW46hEp97sYshZ2aSDAIKYRty3mODPZlM12LL6z1bgbte6bsI3JN0nbIULemfgVqlZAHRDpCv05muEi4IPzYdDxMutAN8zNcMz3IyVoRQ/2bw2kds=" 
  ];

  services.nextcloud = {
    enable = true;                   
    package = pkgs.nextcloud24;
    hostName = "storage.romeov.me";
    https = true;
    config.adminpassFile = "/home/nextcloud_admin_pass";
    home="/storage/nextcloud";
  };

  services.libreddit = {
    enable = true;
    address = "127.0.0.1";
    port = 8081;
  };

  services.nitter = {
    enable = true;
    server = {
      port = 8082;
      https = true;
      hostname = "nitter.romeov.me";
    };
    preferences = {
      replaceTwitter = "nitter.romeov.me";
      hlsPlayback = true;
      muteVideos = true;
      hideTweetStats = true;
    };
  };

  services.mastodon = {
    enable = true;
    localDomain = "social.romeov.me";
    configureNginx = true;
    smtp.fromAddress = "notifications@romeov.me";
  };

  # we need these ports for nextcloud and libreddit
  # open https only(!) (443, but not 80)
  networking.firewall.allowedTCPPorts = [ 443 ];

  # Use nginx and ACME (Let's encrypt) to enable https
  services.nginx = {
    enable = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;
    virtualHosts = {
      "storage.romeov.me" = {
        ## Force HTTP redirect to HTTPS
        forceSSL = true;
        ## LetsEncrypt
        enableACME = true;
      };
      "libreddit.romeov.me" = {
        ## Force HTTP redirect to HTTPS
        forceSSL = true;
        ## LetsEncrypt
        enableACME = true;
        locations."/" = {
          proxyPass = "http://127.0.0.1:8081";
        };
      };
      "nitter.romeov.me" = {
        ## Force HTTP redirect to HTTPS
        forceSSL = true;
        ## LetsEncrypt
        enableACME = true;
        locations."/" = {
          proxyPass = "http://127.0.0.1:8082";
        };
      };
    };
  };
  security.acme = {
    acceptTerms = true;
    defaults.email = "contact@romeov.me";
  };

  # mount hetzner volume
  fileSystems."/storage" =
    { device = "/dev/disk/by-id/scsi-0HC_Volume_23527885";
      fsType = "ext4";
    };

  # set up ipv6
  networking = {
    interfaces.enp1s0.ipv6.addresses = [{
      address = "2a01:4ff:f0:e2df::";
      prefixLength = 64;
    }];
    defaultGateway6 = {
      address = "fe80::1";
      interface = "enp1s0";
    };
  };
}
