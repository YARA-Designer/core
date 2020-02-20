@echo off
SET REMOTE_USER=thehive
SET REMOTE_HOST=thehive-training.vm.local
SET REMOTE_RESPONDERS_DIR=/opt/Cortex-Analyzers/responders

REM Create dir (if not exist)
ssh %REMOTE_USER%@%REMOTE_HOST% "mkdir -pv  %REMOTE_RESPONDERS_DIR%/YaraWhitelistRuleCreator"

REM Upload the latest copy of the responder/ dir to remote.
scp responder\* %REMOTE_USER%@%REMOTE_HOST%:%REMOTE_RESPONDERS_DIR%"/YaraWhitelistRuleCreator"

REM Convert the Windows CR-LF file to UNIX friendly (Required or shebang fails to parse!)
ssh %REMOTE_USER%@%REMOTE_HOST% "dos2unix %REMOTE_RESPONDERS_DIR%"/YaraWhitelistRuleCreator/*.py"

REM Set permissions
ssh %REMOTE_USER%@%REMOTE_HOST% "chmod -v +x %REMOTE_RESPONDERS_DIR%"/YaraWhitelistRuleCreator/*.py"

REM Restart cortex (and thehive, for good measure)
ssh %REMOTE_USER%@%REMOTE_HOST% "sudo systemctl restart cortex thehive"

EXIT