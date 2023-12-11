import { Router } from 'itty-router'
import dayjs from 'dayjs'

export const router = Router({ base: '/api/' })

router.all('*', (request) => {
	if (request.method !== 'POST') {
		return protocolError(400, 'method not allowed')
	}
	if (!request.headers.get('content-type')?.startsWith('application/json')) {
		return protocolError(400, 'unsupported content type')
	}
})

router.post('/list',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const db = env.DB
		const res = await db
			.prepare(`
				select name, created_at
				from repositories
				order by name
			`).all()
		return ok({
			items: res.results.map((x) => ({
				name: x.name,
				createdAt: format(dayjs(x.created_at))
			}))
		})
	}
)

router.post('/get',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { repository } = await request.json() ?? {}
		if (typeof repository !== 'string') {
			return error('repository required')
		}

		const db = env.DB
		const xs = await db.batch([
			db.prepare(`
				select name, created_at
				from repositories
				where name = ?
			`).bind(repository),
			db.prepare(`
				select sum(size) as size
				from blobs
				where repository = ?
			`).bind(repository)
		])

		const repo = xs[0].results[0]
		if (!repo) {
			return error('repository not found')
		}
		const size = xs[1].results[0].size

		return ok({
			name: repo.name,
			size,
			createdAt: format(dayjs(repo.created_at))
		})
	}
)

router.post('/getTags',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { repository } = await request.json() ?? {}
		if (typeof repository !== 'string') {
			return error('repository required')
		}

		const db = env.DB
		const xs = await db.batch([
			db.prepare(`
				select name, created_at
				from repositories
				where name = ?
			`).bind(repository),
			db.prepare(`
				select tag, digest, created_at
				from tags
				where repository = ?
				order by created_at desc
			`).bind(repository)
		])

		const repo = xs[0].results[0]
		if (!repo) {
			return error('repository not found')
		}
		const tags = xs[1].results

		return ok({
			name: repo.name,
			items: tags.map((x) => ({
				tag: x.tag,
				digest: x.digest,
				createdAt: format(dayjs(x.created_at))
			}))
		})
	}
)

router.post('/getManifests',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		const { repository } = await request.json() ?? {}
		if (typeof repository !== 'string') {
			return error('repository required')
		}

		const db = env.DB
		const xs = await db.batch([
			db.prepare(`
				select name, created_at
				from repositories
				where name = ?
			`).bind(repository),
			db.prepare(`
				select digest, created_at
				from manifests
				where repository = ?
				order by created_at desc
			`).bind(repository)
		])

		const repo = xs[0].results[0]
		if (!repo) {
			return error('repository not found')
		}
		const digests = xs[1].results

		return ok({
			name: repo.name,
			items: digests.map((x) => ({
				digest: x.digest,
				createdAt: format(dayjs(x.created_at))
			}))
		})
	}
)

router.all('*', () => {
	return protocolError(400, 'not found')
})

function ok (result) {
	return new Response(JSON.stringify({
		ok: true,
		result
	}), {
		headers: {
			'content-type': 'application/json'
		}
	})
}

function error (message) {
	return new Response(JSON.stringify({
		ok: false,
		error: {
			message
		}
	}), {
		headers: {
			'content-type': 'application/json'
		}
	})
}

function protocolError (status, message) {
	return new Response(JSON.stringify({
		ok: false,
		error: {
			message
		}
	}), {
		status,
		headers: {
			'content-type': 'application/json'
		}
	})
}

/**
 * format formats date to RFC3339 string
 * @param {import('dayjs').Dayjs} date
 * @returns {string}
 */
export function format (date) {
	return date.toISOString().replace(/\..+Z$/, 'Z')
}
