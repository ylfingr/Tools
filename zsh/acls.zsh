#! /bin/zsh

aclsfile=acls

module=${1:-nonexistant}
result="`ruby -e 'require "yaml"; require "json"; y = YAML.load(File.open("acls")); puts y.to_json' | jq '.production|.${module}?'`"
echo "result == <$result>"

#|xargs|tr -d '[] '`"; echo ${${(s:,:)dnu}[3]} )
