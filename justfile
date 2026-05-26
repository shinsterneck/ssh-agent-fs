version := `cargo pkgid | sed 's/.*[#@]//'`

build:
  cargo build --release

licenses:
  cargo about generate about.hbs --output-file licenses.html

release: build licenses
  mkdir -p dist/ssh-agent-fs-{{version}}
  cp target/release/ssh-agent-fs    dist/ssh-agent-fs-{{version}}/
  cp licenses.html README.md LICENSE dist/ssh-agent-fs-{{version}}/
  cp man/ssh-agent-fs.1              dist/ssh-agent-fs-{{version}}/
  tar -C dist -czf ssh-agent-fs-{{version}}.tar.gz ssh-agent-fs-{{version}}
  rm -rf dist

clean:
  cargo clean
  rm -f licenses.html
  rm -f ssh-agent-fs-*.tar.gz
  rm -rf dist
