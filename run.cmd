@echo off
setlocal

set "CMD=%1"
set "ARG=%2"

if "%CMD%"=="" (
    npm run dev
    goto end
)

if /i "%CMD%"=="npm" (
    if "%ARG%"=="" (
        npm run dev
    ) else if /i "%ARG%"=="dev" (
        npm run dev
    ) else if /i "%ARG%"=="start" (
        npm start
    ) else if /i "%ARG%"=="test" (
        npm test
    ) else (
        shift
        npm %*
    )
    goto end
)

if /i "%CMD%"=="dev" (
    npm run dev
    goto end
)

if /i "%CMD%"=="start" (
    npm start
    goto end
)

if /i "%CMD%"=="test" (
    npm test
    goto end
)

npm run %*

:end
endlocal
