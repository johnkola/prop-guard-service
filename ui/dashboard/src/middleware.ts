import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  // Handle authentication routing
  const token = request.cookies.get('token')?.value || 
                request.headers.get('authorization')?.replace('Bearer ', '');
  
  // Define public routes that don't require authentication
  const publicRoutes = ['/login', '/api/v1/auth/login'];
  const isPublicRoute = publicRoutes.some(route => 
    request.nextUrl.pathname === route || request.nextUrl.pathname.startsWith(route)
  );
  
  // If user is not authenticated and trying to access protected route
  if (!token && !isPublicRoute) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
  
  // If user is authenticated and trying to access login page, redirect to dashboard
  if (token && request.nextUrl.pathname === '/login') {
    return NextResponse.redirect(new URL('/', request.url));
  }
  
  // Handle API proxy to backend
  if (request.nextUrl.pathname.startsWith('/api/')) {
    try {
      // Create the backend URL - use container name in Docker
      // Edge Runtime doesn't have process.env access, so we hardcode the Docker service name
      const backendUrl = `http://propguard-backend:8080${request.nextUrl.pathname}${request.nextUrl.search}`;
      
      // Prepare fetch options
      const fetchOptions: RequestInit = {
        method: request.method,
        headers: {
          'Content-Type': 'application/json',
        },
      };
      
      // Only add body for non-GET requests
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        const body = await request.text();
        if (body) {
          fetchOptions.body = body;
        }
      }
      
      // Forward the request to the backend
      const response = await fetch(backendUrl, fetchOptions);
      
      // Get response text
      const responseText = await response.text();
      
      // Return the backend response
      return new NextResponse(responseText, {
        status: response.status,
        statusText: response.statusText,
        headers: {
          'Content-Type': 'application/json',
        },
      });
    } catch (error) {
      console.error('Middleware proxy error:', error);
      return NextResponse.json(
        { error: 'Failed to proxy request' },
        { status: 502 }
      );
    }
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico).*)', // All routes except Next.js assets
  ],
};