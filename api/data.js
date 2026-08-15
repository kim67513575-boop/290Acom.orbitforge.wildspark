const TARGET_URL = 'https://privacy-two-gilt.vercel.app';

export default function handler(request, response) {
  response.setHeader('Content-Type', 'text/plain; charset=utf-8');
  response.setHeader('Access-Control-Allow-Origin', '*');
  response.setHeader('Cache-Control', 'no-store');

  return response.status(200).end(TARGET_URL);
}
