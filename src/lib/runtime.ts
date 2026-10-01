/**
 * Where this console is running: a host installed by deploy/install.sh, or the Docker
 * image (which sets WARDEN_RUNTIME=docker in the image itself, not in any operator file).
 *
 * The console tells people which command to run for host-side steps. Showing a systemd
 * command to someone running containers, or the reverse, is a dead end at exactly the moment
 * they need the step to work — so every such instruction comes from here.
 */
export const IN_DOCKER = process.env.WARDEN_RUNTIME === 'docker';

export const HOST_CMD = IN_DOCKER
  ? {
      gamSetup: 'docker compose run --rm warden gam-setup',
      setupToken: 'docker compose exec warden setup-token',
      claudeLogin: 'docker compose exec -it warden claude\n# then type /login and follow the link',
      enableSweeps:
        '# In the .env file next to docker-compose.yml, set:\nWARDEN_ALLOW_DESTRUCTIVE=1\n# then recreate the containers:\ndocker compose up -d',
      gateWhere:
        'the WARDEN_ALLOW_DESTRUCTIVE variable in the .env file next to docker-compose.yml on the Docker host, which the container cannot write',
      gamPath: '/opt/gam7/gam'
    }
  : {
      gamSetup: 'sudo /opt/warden/deploy/gam-setup.sh',
      setupToken: 'sudo -u warden -H bash -c "cd /opt/warden && npx tsx scripts/setup-token.ts"',
      claudeLogin: 'sudo -u warden -H claude\n# then type /login and follow the link',
      enableSweeps:
        'sudo sed -i "s/WARDEN_ALLOW_DESTRUCTIVE=0/WARDEN_ALLOW_DESTRUCTIVE=1/" \\\n  /etc/systemd/system/warden-web.service.d/10-destructive.conf\nsudo systemctl daemon-reload && sudo systemctl restart warden-web',
      gateWhere:
        'the root-owned systemd drop-in /etc/systemd/system/warden-web.service.d/10-destructive.conf',
      gamPath: '/opt/gam7/gam'
    };
