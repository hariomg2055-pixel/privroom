param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ArgsList
)

if (-not $ArgsList -or $ArgsList.Count -eq 0) {
    npm run dev
    return
}

$first = $ArgsList[0].ToLowerInvariant()

if ($first -eq 'npm') {
    if ($ArgsList.Count -eq 1) {
        npm run dev
        return
    }
    $second = $ArgsList[1].ToLowerInvariant()
    if ($second -eq 'dev') {
        npm run dev
    } elseif ($second -eq 'start') {
        npm start
    } elseif ($second -eq 'test') {
        npm test
    } elseif ($second -eq 'run') {
        if ($ArgsList.Count -gt 2) {
            $rest = $ArgsList[2..($ArgsList.Count - 1)]
            npm run @rest
        } else {
            npm run dev
        }
    } else {
        $rest = $ArgsList[1..($ArgsList.Count - 1)]
        npm @rest
    }
} elseif ($first -eq 'dev') {
    npm run dev
} elseif ($first -eq 'start') {
    npm start
} elseif ($first -eq 'test') {
    npm test
} else {
    npm run @ArgsList
}
