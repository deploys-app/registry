import { Router } from 'itty-router'
import { router as registry } from './registry'
import { router as api } from './api'
import { authorized } from './auth'

const router = Router()

router.all('/v2/*', authorized, registry.handle)
router.all('/api/*', api.handle)

router.get('/',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		return new Response('Deploys.app Registry Service')
	}
)

router.all('*',
	/**
	 * @param {import('itty-router').IRequest} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 */
	async (request, env, ctx) => {
		return new Response('404 page not found', {
			status: 404
		})
	}
)

/**
 * @typedef Env
 * @property {import('@cloudflare/workers-types').R2Bucket} BUCKET
 * @property {import('@cloudflare/workers-types').D1Database} DB
 * @property {import('@cloudflare/workers-types').AnalyticsEngineDataset} ANALYTICS
 */

export default {
	/**
	 * @param {import('@cloudflare/workers-types').Request} request
	 * @param {Env} env
	 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
	 * @returns {Promise<import('@cloudflare/workers-types').Response>}
	 **/
	fetch (request, env, ctx) {
		return router.handle(request, env, ctx)
	}
}
