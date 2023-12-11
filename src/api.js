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

router.post('/getRepositories',
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

router.post('/getRepository',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		/**
		 * @property {string} repository
		 */
		const req = await request.json()
		if (!req) {
			return error('invalid request')
		}
		if (typeof req.repository !== 'string') {
			return error('repository required')
		}

		const db = env.DB
		const repo = await db.prepare(`
			select name, created_at
			from repositories
			where name = ?
		`).bind(req.repository).first()
		if (!repo) {
			return error('repository not found')
		}
		const xs = await db.batch([
			db.prepare(`
				select digest, created_at
				from manifests
				where repository = ?
				order by created_at desc
			`).bind(req.repository),
			db.prepare(`
				select tag, digest, created_at
				from tags
				where repository = ?
				order by created_at desc
			`).bind(req.repository)
		])

		return ok({
			name: repo.name,
			createdAt: format(dayjs(repo.created_at)),
			digests: xs[0].results.map((x) => ({
				digest: x.digest,
				createdAt: format(dayjs(x.created_at))
			})),
			tags: xs[1].results.map((x) => ({
				tag: x.tag,
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
