import { UnauthorizedError, registryErrorResponse } from './registry'

const authEndpoint = 'https://api.deploys.app/me.authorized'
const infoEndpoint = 'https://api.deploys.app/me.get'

export const pullPermission = 'registry.pull'
export const pushPermission = 'registry.push'
export const listPermission = 'registry.list'
export const getPermission = 'registry.get'

/**
 * @param {import('itty-router').IRequest} request
 * @param {Env} env
 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
 * @returns {Promise<import('@cloudflare/workers-types').Response | undefined>}
 */
export async function authorized (request, env, ctx) {
	const unauthorizedResponse = registryErrorResponse(401, UnauthorizedError)
	unauthorizedResponse.headers.set('www-authenticate', `basic realm=${request.url}`)

	const auth = request.headers.get('authorization')
	if (!auth) {
		return unauthorizedResponse
	}

	const url = new URL(request.url)
	if (url.pathname === '/v2/') {
		const email = await getEmail(auth, env, ctx)
		if (!email) {
			return unauthorizedResponse
		}
		return // authorized
	}

	const project = url.pathname.match(/^\/v2\/([^/]*)\/.*$/)?.[1]
	if (!project) {
		return unauthorizedResponse
	}
	request.namespace = project

	// push permission can do both push and pull
	if (await checkPermission(auth, project, pushPermission, env, ctx)) {
		return // authorized
	}

	// user don't have push permission
	if (isPushRequest(request)) {
		// so reject push request
		return unauthorizedResponse
	}

	if (await checkPermission(auth, project, pullPermission, env, ctx)) {
		return // authorized
	}

	// user don't have any permission
	return unauthorizedResponse
}

/**
 * @param {import('itty-router').IRequest} request
 * @returns {boolean}
 */
function isPushRequest (request) {
	return !{
		GET: true,
		HEAD: true
	}[request.method]
}

/**
 * @param {string} auth
 * @param {Env} env
 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
 * @returns {Promise<?string>}
 */
async function getEmail (auth, env, ctx) {
	const cache = caches.default
	const cacheKey = `deploys--registry|info|${auth}`
	const cacheReq = new Request(infoEndpoint, {
		cf: {
			cacheTtl: 30,
			cacheKey,
			cacheTags: ['deploys--registry|info']
		}
	})
	let resp = await cache.match(cacheReq)
	if (!resp) {
		resp = await fetch(infoEndpoint, {
			method: 'POST',
			headers: {
				authorization: auth,
				'content-type': 'application/json'
			},
			body: JSON.stringify({})
		})
		if (!resp.ok) {
			return ''
		}

		// cache
		const cacheResp = new Response(resp.clone().body, resp)
		cacheResp.headers.set('cache-control', 'public, max-age=30')
		ctx.waitUntil(cache.put(cacheReq, cacheResp))
	}

	const res = await resp.json()
	if (!res.ok) {
		return ''
	}
	return res.result.email
}

/**
 * @param {string} auth
 * @param {string} project
 * @param {string} permission
 * @param {Env} env
 * @param {import('@cloudflare/workers-types').ExecutionContext} ctx
 * @returns {Promise<boolean>}
 */
export async function checkPermission (auth, project, permission, env, ctx) {
	if (!auth) {
		return false
	}

	const cache = caches.default
	const cacheKey = `deploys--registry|auth|${project}|${permission}|${auth}`
	const cacheReq = new Request(authEndpoint, {
		cf: {
			cacheTtl: 30,
			cacheKey,
			cacheTags: ['deploys--registry|auth']
		}
	})
	let resp = await cache.match(cacheReq)
	if (!resp) {
		resp = await fetch(authEndpoint, {
			method: 'POST',
			headers: {
				authorization: auth,
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				project,
				permissions: [permission]
			})
		})
		if (!resp.ok) {
			return false
		}

		const cacheResp = new Response(resp.clone().body, resp)
		cacheResp.headers.set('cache-control', 'public, max-age=30')
		ctx.waitUntil(cache.put(cacheReq, cacheResp))
	}

	const res = await resp.json()
	return res.ok && res.result.authorized && res.result.project.billingAccount.active
}
