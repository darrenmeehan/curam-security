//! Minimal POSIX shell word splitter matching Python's `shlex.split` for the
//! command shapes the policy sees. `Err` mirrors Python's `ValueError` on
//! unterminated quotes / trailing backslash — both map to "unparseable → ask".

/// Split a command string into argv. `Err(())` on unterminated quote or a
/// dangling backslash (Python `shlex.split` raises `ValueError` there).
pub fn split(command: &str) -> Result<Vec<String>, ()> {
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut it = command.chars().peekable();

    while let Some(c) = it.next() {
        match c {
            // Python shlex splits on any whitespace
            ' ' | '\t' | '\n' | '\r' | '\u{000b}' | '\u{000c}' => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match it.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => return Err(()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match it.next() {
                        Some('"') => break,
                        // In double quotes Python only backslash-escapes a few
                        // metachars; anything else keeps the backslash.
                        Some('\\') => match it.next() {
                            Some('\\') | Some('"') | Some('$') | Some('`') | Some('\n') => {}
                            Some(ch) => {
                                cur.push('\\');
                                cur.push(ch);
                            }
                            None => return Err(()),
                        },
                        Some(ch) => cur.push(ch),
                        None => return Err(()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match it.next() {
                    Some(ch) => cur.push(ch),
                    None => return Err(()), // trailing backslash
                }
            }
            _ => {
                in_word = true;
                cur.push(c);
            }
        }
    }

    if in_word {
        words.push(cur);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_plain_words() {
        assert_eq!(split("ls -la").unwrap(), vec!["ls", "-la"]);
        assert_eq!(split("echo hi").unwrap(), vec!["echo", "hi"]);
        assert_eq!(split("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn handles_quotes() {
        assert_eq!(split("bash -c 'echo hi'").unwrap(), vec!["bash", "-c", "echo hi"]);
        assert_eq!(split("echo \"a b\"").unwrap(), vec!["echo", "a b"]);
        // unterminated quote -> Err (Python raises ValueError)
        assert!(split("echo 'oops").is_err());
    }

    #[test]
    fn handles_backslash() {
        assert_eq!(split(r"echo \*").unwrap(), vec!["echo", "*"]);
        assert!(split("echo \\").is_err()); // trailing backslash
    }

    #[test]
    fn handles_pipes_and_dollar() {
        assert_eq!(
            split("echo '$(' whoami )").unwrap(),
            vec!["echo", "$(", "whoami", ")"]
        );
    }
}