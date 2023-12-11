const endpoint = 'https://registry.moonrhythm.io'

async function getRepositories () {
	const resp = await fetch(`${endpoint}/api/getRepositories`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json'
		},
		body: JSON.stringify({})
	})
	if (!resp.ok) throw new Error(resp.statusText)
	const { result } = await resp.json()
	return result.items.map((x) => x.name)
}

async function sync (repo) {
	const resp = await fetch(`${endpoint}/v2/${repo}/tags/list`)
	if (!resp.ok) throw new Error(resp.statusText)
	const { name, tags } = await resp.json()
	return Promise.all(
		tags
			.filter((tag) => !isSHA256(tag))
			.map(async (tag) => {
				const digest = await getDigest(repo, tag)
				if (!digest) throw new Error(`no digest, ${repo}:${tag}`)
				return {
					repository: name,
					digest,
					tag
				}
			})
	)
}

async function getDigest (repo, tag) {
	const resp = await fetch(`${endpoint}/v2/${repo}/manifests/${tag}`)
	if (!resp.ok) throw new Error(resp.statusText)
	let { digest } = (await resp.json()).config ?? ''
	if (!digest) {
		digest = resp.headers.get('docker-content-digest')
	}
	if (!digest) {
		throw new Error(`no digest, ${repo}:${tag}`)
	}
	return digest
}

async function main () {
	const list = await getRepositories()
	const sql = (await Promise.all(list.map(sync)))
		.flat()
		.reduce((p, v, i) => {
			return [
				`${p[0]}\n  ${i > 0 ? ',' : ' '} ('${v.repository}', '${v.digest}')`,
				`${p[1]}\n  ${i > 0 ? ',' : ' '} ('${v.repository}', '${v.tag}', '${v.digest}')`
			]
		}, [
			'insert into manifests (repository, digest) values',
			'insert into tags (repository, tag, digest) values'
		])
		.map((x) => `${x}\non conflict do nothing;`)
		.join('\n')
	console.log(sql)
}

main()

function isSHA256 (str) {
	return str.startsWith('sha256:')
}
