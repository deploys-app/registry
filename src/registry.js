import { Router } from 'itty-router'

const ChunkMinLength = 5 << 10 * 2 // 5 MiB

export const router = Router({ base: '/v2/' })

// https://github.com/opencontainers/distribution-spec/blob/main/spec.md

// end-1
router.get('/',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		return new Response('ok')
	}
)

// end-2 GET
router.get('/:name+/blobs/:digest+',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name, digest } = request.params

		const cache = caches.default
		{
			const resp = await cache.match(request)
			if (resp) {
				env.ANALYTICS.writeDataPoint({
					blobs: ['get-blobs', request.namespace, 'hit'],
					doubles: [resp.headers.get('content-length')],
					indexes: [request.namespace]
				})
				return resp
			}
		}

		const res = await env.BUCKET.get(`${name}/blobs/${digest}`)
		if (!res) {
			return registryErrorResponse(404, BlobUnknownError)
		}

		const resp = new Response(res.body, {
			headers: {
				'docker-content-digest': hexToDigest(res.checksums.sha256),
				'content-length': res.size,
				'cache-control': 'public, max-age=31536000; immutable'
			}
		})
		ctx.waitUntil(cache.put(request, resp.clone()))
		env.ANALYTICS.writeDataPoint({
			blobs: ['get-blobs', request.namespace, 'miss'],
			doubles: [res.size],
			indexes: [request.namespace]
		})

		return resp
	}
)

// end-2 HEAD
router.head('/:name+/blobs/:digest+',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name, digest } = request.params

		const res = await env.BUCKET.head(`${name}/blobs/${digest}`)
		if (!res) {
			return registryErrorResponse(404, BlobUnknownError)
		}

		return new Response(null, {
			headers: {
				'docker-content-digest': hexToDigest(res.checksums.sha256),
				'content-length': res.size
			}
		})
	}
)

// end-3 GET
router.get('/:name+/manifests/:reference',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name, reference } = request.params

		const cache = caches.default
		{
			const resp = await cache.match(request)
			if (resp) {
				env.ANALYTICS.writeDataPoint({
					blobs: ['get-manifests', request.namespace, 'hit'],
					doubles: [resp.headers.get('content-length')],
					indexes: [request.namespace]
				})
				return resp
			}
		}

		const res = await env.BUCKET.get(`${name}/manifests/${reference}`)
		if (!res) {
			return registryErrorResponse(404, ManifestUnknownError)
		}

		const resp = new Response(res.body, {
			headers: {
				'docker-content-digest': hexToDigest(res.checksums.sha256),
				'content-length': res.size,
				'content-type': res.httpMetadata.contentType,
				'cache-control': reference.startsWith('sha256:')
					? 'public, max-age=86400'
					: 'public, max-age=600'
			}
		})
		ctx.waitUntil(cache.put(request, resp.clone()))
		env.ANALYTICS.writeDataPoint({
			blobs: ['get-manifest', request.namespace, 'miss'],
			doubles: [res.size],
			indexes: [request.namespace]
		})

		return resp
	}
)

// end-3 HEAD
router.head('/:name+/manifests/:reference',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name, reference } = request.params

		const res = await env.BUCKET.head(`${name}/manifests/${reference}`)
		if (!res) {
			return registryErrorResponse(404, ManifestUnknownError)
		}

		return new Response(null, {
			headers: {
				'docker-content-digest': hexToDigest(res.checksums.sha256),
				'content-length': res.size,
				'content-type': res.httpMetadata.contentType
			}
		})
	}
)

/**
 * @typedef UploadState
 * @property {number} size
 * @property {import('@cloudflare/workers-types').R2UploadedPart[]} parts
 */

// end-4,11
// end-4a /v2/<name>/blobs/uploads/
// end-4b /v2/<name>/blobs/uploads/?digest=<digest>
// end-11 /v2/<name>/blobs/uploads/?mount=<digest>&from=<other_name>
router.post('/:name+/blobs/uploads/',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name } = request.params
		const { digest, mount, from, origin } = request.query

		// end-11
		if (mount && from) {
			const res = await env.BUCKET.head(`${name}/blobs/${mount}`)
			if (res) { // already exists, skip upload
				return new Response(null, {
					status: 201,
					headers: {
						location: `/v2/${name}/blobs/${mount}`,
						'docker-content-digest': mount
					}
				})
			}

			if (origin) { // cross-origin mount
				const resp = await fetch(`https://${origin}/v2/${from}/blobs/${mount}`, {
					redirect: 'follow'
				})
				if (resp.ok) { // not ok fallback to end-4a
					const size = parseInt(resp.headers.get('content-length') ?? '0')
					await env.BUCKET.put(`${name}/blobs/${mount}`, resp.body, {
						sha256: digestToSHA256(mount)
					})
					ctx.waitUntil(insertBlob(env.DB, name, mount, size))
					return new Response(null, {
						status: 201,
						headers: {
							location: `/v2/${name}/blobs/${mount}`,
							'docker-content-digest': mount
						}
					})
				}
			} else { // mount from same registry but other namespace
				const res = await env.BUCKET.get(`${from}/blobs/${mount}`)
				if (res) { // object not found, fallback to end-4a
					await env.BUCKET.put(`${name}/blobs/${mount}`, res.body, {
						sha256: digestToSHA256(mount)
					})
					ctx.waitUntil(insertBlob(env.DB, name, mount, res.size))
					return new Response(null, {
						status: 201,
						headers: {
							location: `/v2/${name}/blobs/${mount}`,
							'docker-content-digest': mount
						}
					})
				}
			}
		}

		// end-4b
		if (digest) {
			const res = await env.BUCKET.head(`${name}/blobs/${digest}`)
			if (!res) { // not exists, then put to bucket
				await env.BUCKET.put(`${name}/blobs/${digest}`, request.body, {
					sha256: digestToSHA256(digest)
				})
				ctx.waitUntil(insertBlob(env.DB, name, digest, res.size))
			}
			return new Response(null, {
				status: 201,
				headers: {
					location: `/v2/${name}/blobs/${digest}`,
					'docker-content-digest': digest
				}
			})
		}

		// end-4a
		// step: end-4a => [end-5]* => end-6

		const reference = crypto.randomUUID()
		const upload = await env.BUCKET.createMultipartUpload(`_uploads/${reference}`)
		/** @type {UploadState} */
		const uploadState = {
			size: 0,
			parts: []
		}

		return new Response(null, {
			status: 202,
			headers: {
				location: uploadLocation(name, reference, upload.uploadId, uploadState),
				'oci-chunk-min-length': ChunkMinLength
			}
		})
	}
)

// end-5
// /v2/<name>/blobs/uploads/<reference>?upload=<uploadId>&state=<state>
router.patch('/:name+/blobs/uploads/:reference',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name, reference } = request.params
		const { upload: uploadId, state } = request.query
		if (typeof uploadId !== 'string' || typeof state !== 'string') {
			return registryErrorResponse(400, UnsupportedError)
		}
		const length = parseInt(request.headers.get('content-length') ?? '0')
		if (!length) {
			return registryErrorResponse(400, UnsupportedError) // body exceed cloudflare allow
		}
		const contentRange = request.headers.get('content-range')
		const [rangeStart, rangeEnd] = contentRange
			? contentRange.split('-')
			: ['0', '' + length]
		if (!rangeStart || !rangeEnd) {
			return registryErrorResponse(400, UnsupportedError)
		}

		/** @type {UploadState} */
		const uploadState = JSON.parse(state)
		if (!uploadState) {
			return registryErrorResponse(400, UnsupportedError)
		}

		if (uploadState.size !== +rangeStart) {
			return new Response(null, {
				status: 416
			})
		}
		if (uploadState.parts.length >= 10000) { // r2 limitation
			return new Response(null, {
				status: 500
			})
		}

		const upload = env.BUCKET.resumeMultipartUpload(`_uploads/${reference}`, uploadId)
		const part = await upload.uploadPart(uploadState.parts.length + 1, request.body)
		uploadState.parts.push(part)
		uploadState.size += length

		return new Response(null, {
			status: 202,
			headers: {
				location: uploadLocation(name, reference, uploadId, uploadState)
			}
		})
	}
)

// end-6
// /v2/<name>/blobs/uploads/<reference>?upload=<uploadId>&state=<state>&digest=<digest>
router.put('/:name+/blobs/uploads/:reference',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name, reference } = request.params
		const { upload: uploadId, state, digest } = request.query
		if (typeof uploadId !== 'string' ||
			typeof state !== 'string' ||
			typeof digest !== 'string') {
			return registryErrorResponse(400, UnsupportedError)
		}

		/** @type {UploadState} */
		const uploadState = JSON.parse(state)
		if (!uploadState) {
			return registryErrorResponse(400, UnsupportedError)
		}

		const upload = env.BUCKET.resumeMultipartUpload(`_uploads/${reference}`, uploadId)

		const length = parseInt(request.headers.get('content-length') ?? '0')
		if (length > 0) {
			const part = await upload.uploadPart(uploadState.parts.length + 1, request.body)
			uploadState.parts.push(part)
		}
		await upload.complete(uploadState.parts)

		// copy completed object to blob
		{
			const upload = await env.BUCKET.get(`_uploads/${reference}`)
			await env.BUCKET.put(`${name}/blobs/${digest}`, upload.body, {
				sha256: digestToSHA256(digest)
			})
			await env.BUCKET.delete(`_uploads/${reference}`)
			ctx.waitUntil(insertBlob(env.DB, name, digest, upload.size))
			env.ANALYTICS.writeDataPoint({
				blobs: ['put-blobs', request.namespace],
				doubles: [upload.size],
				indexes: [request.namespace]
			})
		}

		return new Response(null, {
			status: 201,
			headers: {
				location: `/v2/${name}/blobs/${digest}`,
				'docker-content-digest': digest
			}
		})
	}
)

// end-7
router.put('/:name+/manifests/:reference',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name, reference } = request.params

		const contentType = request.headers.get('content-type')
		if (!contentType) {
			return registryErrorResponse(400, UnsupportedError)
		}

		const sha256 = new crypto.DigestStream('SHA-256')
		const bodyStream = request.body.getReader()
		const shaStream = sha256.getWriter()

		/** @type {Blob} */
		let blob
		{
			// read body to sha and blob
			const bs = []
			while (true) {
				const v = await bodyStream.read()
				if (v.done) {
					break
				}
				bs.push(v.value)
				await shaStream.write(v.value)
			}
			blob = new Blob(bs)
		}

		bodyStream.releaseLock()
		shaStream.close()

		const digest = hexToDigest(await sha256.digest)

		await Promise.all([
			env.BUCKET.put(`${name}/manifests/${digest}`, blob, {
				sha256: digestToSHA256(digest),
				httpMetadata: {
					contentType
				}
			}),
			digest !== reference
				? env.BUCKET.put(`${name}/manifests/${reference}`, blob, {
					sha256: digestToSHA256(digest),
					httpMetadata: {
						contentType
					}
				})
				: null
		])

		const db = env.DB
		const batch = [
			db.prepare(`
				insert into repositories (name, namespace)
				values (?, ?)
				on conflict do nothing
			`).bind(name, request.namespace),
			db.prepare(`
				insert into manifests (repository, digest)
				values (?, ?)
				on conflict do nothing
			`).bind(name, digest)
		]
		if (digest !== reference) {
			batch.push(
				db.prepare(`
					insert into tags (repository, tag, digest)
					values (?, ?, ?)
					on conflict (repository, tag)
					do update
					    set digest = excluded.digest,
					        created_at = current_timestamp
				`).bind(name, reference, digest)
			)
		}
		ctx.waitUntil(db.batch(batch))
		env.ANALYTICS.writeDataPoint({
			blobs: ['put-manifest', request.namespace],
			doubles: [blob.size],
			indexes: [request.namespace]
		})

		return new Response(null, {
			status: 201,
			headers: {
				location: `/v2/${name}/manifests/${reference}`,
				'docker-content-digest': digest
			}
		})
	}
)

// end-8
router.get('/:name+/tags/list',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name } = request.params
		const { n, last } = request.query

		const limit = typeof n === 'string' ? parseInt(n) : 50
		const startAfter = typeof last === 'string' ? last : undefined

		const res = await env.BUCKET.list({
			prefix: `${name}/manifests`,
			limit,
			startAfter
		})

		const tags = res.objects
			.map((x) => x.key.split('/').pop())
		const lastKey = tags.length > 0 ? tags[tags.length - 1] : ''

		let link = ''
		if (tags.length >= n) {
			const qs = new URLSearchParams({ n: '' + limit, last: lastKey })
			const url = new URL(request.url)
			url.search = qs.toString()
			link = url.toString()
		}

		return new Response(JSON.stringify({ name, tags }), {
			headers: {
				'content-type': 'application/json',
				...link ? { link: `<${link}>; rel=next` } : null
			}
		})
	}
)

// end-9
router.delete('/:name+/manifests/:reference',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name, reference } = request.params

		const res = await env.BUCKET.head(`${name}/manifests/${reference}`)
		if (!res) {
			return registryErrorResponse(404, ManifestUnknownError)
		}

		// TODO: remove manifests sha256 that matches with ref ? or send 2 request to delete, tag and ref
		// TODO: cronjob delete no ref blobs

		await env.BUCKET.delete(`${name}/manifests/${reference}`)

		if (isSHA256(reference)) {
			ctx.waitUntil(env.DB.prepare(`
				delete from manifests
				where repository = ? and digest = ?
			`).bind(name, reference).run())
		} else {
			ctx.waitUntil(env.DB.prepare(`
				delete from tags
				where repository = ? and tag = ?
			`).bind(name, reference).run())
		}
		env.ANALYTICS.writeDataPoint({
			blobs: ['delete-manifest', request.namespace],
			doubles: [res.size],
			indexes: [request.namespace]
		})

		return new Response(null, {
			status: 202
		})
	}
)

// end-10
router.delete('/:name+/blobs/:digest',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name, digest } = request.params

		const res = await env.BUCKET.head(`${name}/blobs/${digest}`)
		if (!res) {
			return registryErrorResponse(404, BlobUnknownError)
		}

		await env.BUCKET.delete(`${name}/blobs/${digest}`)
		ctx.waitUntil(env.DB.prepare(`
			delete from blobs
			where repository = ? and digest = ?
		`).bind(name, digest).run())
		env.ANALYTICS.writeDataPoint({
			blobs: ['delete-blob', request.namespace],
			doubles: [res.size],
			indexes: [request.namespace]
		})

		return new Response(null, {
			status: 202
		})
	}
)

// end-13
// /v2/<name>/blobs/uploads/<reference>?upload=<uploadId>&state=<state>
router.get('/:name+/blobs/uploads/:reference',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { name, reference } = request.params
		const { upload: uploadId, state } = request.query
		if (typeof uploadId !== 'string' || typeof state !== 'string') {
			return registryErrorResponse(400, UnsupportedError)
		}

		/** @type {UploadState} */
		const uploadState = JSON.parse(state)
		if (!uploadState) {
			return registryErrorResponse(400, UnsupportedError)
		}

		return new Response(null, {
			status: 204,
			headers: {
				location: uploadLocation(name, reference, uploadId, uploadState),
				range: `0-${uploadState.size}`
			}
		})
	}
)

function hexToDigest (s) {
	const digest = [...new Uint8Array(s)]
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('')
	return `sha256:${digest}`
}

// errors

/**
 * @typedef RegistryError
 * @property {string} code
 * @property {string} message
 * @property {string} detail
 */

// code-1
/** @type {RegistryError} */
export const BlobUnknownError = {
	code: 'BLOB_UNKNOWN',
	message: 'blob unknown to registry',
	detail: 'blob unknown to registry'
}

// code-3
/** @type {RegistryError} */
export const BlobUploadUnknownError = {
	code: 'BLOB_UPLOAD_UNKNOWN',
	message: 'blob upload unknown to registry',
	detail: 'blob upload unknown to registry'
}

// code-7
/** @type {RegistryError} */
export const ManifestUnknownError = {
	code: 'MANIFEST_UNKNOWN',
	message: 'manifest unknown to registry',
	detail: 'manifest unknown to registry'
}

// code-11
/** @type {RegistryError} */
export const UnauthorizedError = {
	code: 'UNAUTHORIZED',
	message: 'authentication required',
	detail: 'authentication required'
}

// code-13
/** @type {RegistryError} */
export const UnsupportedError = {
	code: 'UNSUPPORTED',
	message: 'the operation is unsupported',
	detail: 'the operation is unsupported'
}

/**
 * @typedef RegistryErrorResult
 * @property {RegistryError[]} errors
 */

/**
 * Generates a registry error response.
 * @param {number} status - http status code
 * @param {...RegistryError} errors - The error(s) to include in the response.
 * @returns {import('@cloudflare/workers-types').Response}
 */
export function registryErrorResponse (status, ...errors) {
	return new Response(JSON.stringify({
		errors
	}), {
		status,
		headers: {
			'content-type': 'application/json'
		}
	})
}

const sha256PrefixLength = 'sha256:'.length

/**
 *
 * @param {string} digest
 * @returns {string}
 */
function digestToSHA256 (digest) {
	return digest.slice(sha256PrefixLength)
}

/**
 * @param {string} digest
 * @returns {boolean}
 */
function isSHA256 (digest) {
	return digest.startsWith('sha256:')
}

/**
 * @param {string} name
 * @param {string} reference
 * @param {string} uploadId
 * @param {UploadState} uploadState
 * @returns {string}
 */
function uploadLocation (name, reference, uploadId, uploadState) {
	const state = encodeURIComponent(JSON.stringify(uploadState))
	return `/v2/${name}/blobs/uploads/${reference}?upload=${uploadId}&state=${state}`
}

/**
 * @param {import('@cloudflare/workers-types').D1Database} db
 * @param {string} name
 * @param {string} digest
 * @param {number} size
 * @returns {Promise<import('@cloudflare/workers-types').D1Result>}
 */
function insertBlob (db, name, digest, size) {
	return db.prepare(`
		insert into blobs (repository, digest, size)
		values (?, ?, ?)
		on conflict do nothing
	`).bind(name, digest, size).run()
}
