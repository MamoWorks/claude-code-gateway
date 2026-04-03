@echo off
REM Dev: build frontend + run Rust backend
setlocal

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%.."

REM Build frontend if dist not exists
if not exist "web\dist" (
    echo Building frontend...
    pushd web
    if not exist "node_modules\@vue\tsconfig" (
        echo Installing frontend dependencies...
        call npm install
        if errorlevel 1 (
            popd
            popd
            exit /b 1
        )
    )
    call npm run build
    if errorlevel 1 (
        popd
        popd
        exit /b 1
    )
    popd
)

REM Run
cargo run %*
popd
