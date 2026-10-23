//! Whether an executable is the program a token was issued for (acwbroker
//! `domain/model/callerrule.go`).

use crate::issue::Rule;

/// The part of an executable's version resource a caller rule compares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageMetadata {
    pub company: String,
    pub product: String,
    pub original_filename: String,
}

impl ImageMetadata {
    pub fn new(company: &str, product: &str, original_filename: &str) -> Self {
        ImageMetadata {
            company: company.to_owned(),
            product: product.to_owned(),
            original_filename: original_filename.to_owned(),
        }
    }
}

/// Reads an executable's version resource.
pub type ReadMetadata<'a> = &'a dyn Fn(&str) -> Result<ImageMetadata, String>;

/// Whether `image` is `rule`'s program, or why not. `metadata` is asked only when the folder
/// did not decide. No rule, or kind 0, admits everything.
pub fn admits(
    rule: Option<&Rule>,
    image: &str,
    metadata: Option<ReadMetadata<'_>>,
) -> Result<(), String> {
    let Some(rule) = rule.filter(|r| r.kind != 0) else {
        return Ok(());
    };
    if image.is_empty() {
        return Err("the caller's executable could not be read".to_owned());
    }
    let path = String::from_utf8_lossy(&rule.path);
    if rule
        .extra_paths
        .iter()
        .any(|p| same_path(image, &String::from_utf8_lossy(p)))
    {
        return Ok(());
    }
    let same_folder = || same_path(&dir(image), &dir(&path));
    match rule.kind {
        1 if same_path(image, &path) => Ok(()),
        1 => Err(format!("{image} is not {path}")),
        2 if same_folder() => Ok(()),
        2 => Err(format!("{image} is not in the folder of {path}")),
        3 if same_folder() => Ok(()),
        3 => {
            let Some(read) = metadata else {
                return Err(format!(
                    "{image} is not in the folder of {path}, and its version resource cannot be read here"
                ));
            };
            let m = read(image).map_err(|e| {
                format!("{image} is not in the folder of {path}, and its version resource: {e}")
            })?;
            let (company, product, original) = match &rule.metadata {
                Some((c, p, o)) => (
                    String::from_utf8_lossy(c),
                    String::from_utf8_lossy(p),
                    String::from_utf8_lossy(o),
                ),
                None => Default::default(),
            };
            if m.company.contains(&*company)
                && m.product.contains(&*product)
                && m.original_filename == original
            {
                Ok(())
            } else {
                Err(format!(
                    "{image} is not in the folder of {path}, and its version resource ({:?}, {:?}, {:?}) is not the program's",
                    m.company, m.product, m.original_filename
                ))
            }
        }
        k => Err(format!("unknown rule kind {k}")),
    }
}

fn same_path(a: &str, b: &str) -> bool {
    let (a, b) = (clean(a), clean(b));
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}

fn is_separator(c: char) -> bool {
    c == '\\' || c == '/'
}

/// The volume a Windows path starts with: `C:`, or `\\host\share`.
fn volume(path: &str) -> usize {
    let b = path.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return 2;
    }
    if b.len() >= 2 && is_separator(char::from(b[0])) && is_separator(char::from(b[1])) {
        let mut parts = 0;
        for (i, c) in path.char_indices().skip(2) {
            if is_separator(c) {
                parts += 1;
                if parts == 2 {
                    return i;
                }
            }
        }
        return path.len();
    }
    0
}

/// `path` cleaned lexically as Go's `filepath.Clean` cleans a Windows path.
fn clean(path: &str) -> String {
    let v = volume(path);
    let (vol, rest) = path.split_at(v);
    let vol = vol.replace('/', "\\");
    if rest.is_empty() {
        return if vol.is_empty() { ".".to_owned() } else { vol };
    }
    let rooted = rest.starts_with(is_separator);
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split(is_separator) {
        match part {
            "" | "." => {}
            ".." => match parts.last() {
                Some(&p) if p != ".." => {
                    parts.pop();
                }
                _ if rooted => {}
                _ => parts.push(".."),
            },
            p => parts.push(p),
        }
    }
    let mut out = String::from(if rooted { "\\" } else { "" });
    out.push_str(&parts.join("\\"));
    if out.is_empty() {
        out.push('.');
    }
    vol + &out
}

/// Everything in `path` but its last element, cleaned, as Go's `filepath.Dir` gives it.
fn dir(path: &str) -> String {
    let v = volume(path);
    let end = path[v..].rfind(is_separator).map_or(v, |i| v + i + 1);
    let d = clean(&path[v..end]);
    if d == "." && v > 2 {
        return path[..v].to_owned();
    }
    path[..v].replace('/', "\\") + &d
}
