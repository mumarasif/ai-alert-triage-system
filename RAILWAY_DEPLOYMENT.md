# Railway Deployment Guide for AI Alert Triage System

This guide will help you deploy your AI Alert Triage System to Railway, a modern cloud platform for deploying applications.

## Prerequisites

1. **GitHub Repository**: Your code should be pushed to a GitHub repository
2. **Railway Account**: Sign up at [railway.app](https://railway.app)
3. **Supabase Account**: For database (if not already set up)
4. **LLM API Key**: OpenAI or other LLM provider API key

## Step 1: Deploy to Railway

### Option A: Deploy via Railway Dashboard (Recommended)

1. **Connect GitHub Repository**:
   - Go to [railway.app](https://railway.app) and sign in
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your `ai-alert-triage-system` repository
   - Click "Deploy"

2. **Configure Build Settings**:
   - Railway will automatically detect this is a Python project
   - The `Procfile` will be used for the start command
   - Build will use the `requirements.txt` file

### Option B: Deploy via Railway CLI

1. **Install Railway CLI**:
   ```bash
   npm install -g @railway/cli
   ```

2. **Login to Railway**:
   ```bash
   railway login
   ```

3. **Deploy from your project directory**:
   ```bash
   railway init
   railway up
   ```

## Step 2: Configure Environment Variables

In your Railway project dashboard, go to the "Variables" tab and add the following environment variables:

### Required Variables

```bash
# LLM Configuration
LLM_API_KEY=your-openai-api-key-here

# Supabase Database Configuration
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_SERVICE_KEY=your-service-role-key-here

# Security Configuration
WEBHOOK_SECRET=your-webhook-secret-here
JWT_SECRET=your-jwt-secret-here
```

### Optional Variables

```bash
# System Configuration
LOG_LEVEL=INFO
DEBUG_MODE=false
TEST_MODE=false

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=1000

# Monitoring
METRICS_ENABLED=true
METRICS_INTERVAL=60

# Frontend Integration
FRONTEND_URL=https://your-frontend-domain.com
API_BASE_URL=https://your-railway-app.railway.app
```

## Step 3: Database Setup

### Supabase Setup

1. **Create Supabase Project**:
   - Go to [supabase.com](https://supabase.com)
   - Create a new project
   - Note down your project URL and service role key

2. **Run Database Schema**:
   - Use the SQL files in your repository:
     - `database_schema.sql` (comprehensive schema)
     - `database_schema_simple.sql` (simplified schema)
   - Copy and paste the SQL into your Supabase SQL editor
   - Execute the schema

3. **Update Environment Variables**:
   - Add your Supabase URL and service key to Railway environment variables

## Step 4: Verify Deployment

Once deployed, your application will be available at:
- **Main App**: `https://your-app-name.railway.app`
- **Health Check**: `https://your-app-name.railway.app/health`
- **API Docs**: `https://your-app-name.railway.app/docs`
- **Metrics**: `https://your-app-name.railway.app/metrics`

### Test Endpoints

1. **Health Check**:
   ```bash
   curl https://your-app-name.railway.app/health
   ```

2. **Send Test Alert**:
   ```bash
   curl -X POST https://your-app-name.railway.app/webhook/alert \
     -H "Content-Type: application/json" \
     -d '{
       "id": "test-alert-001",
       "type": "security_alert",
       "description": "Test security alert",
       "severity": "high",
       "source_ip": "192.168.1.100",
       "hostname": "test-server"
     }'
   ```

## Step 5: Configure Custom Domain (Optional)

1. **Add Custom Domain**:
   - In Railway dashboard, go to "Settings" → "Domains"
   - Add your custom domain
   - Configure DNS records as instructed

2. **Update Environment Variables**:
   - Update `API_BASE_URL` to use your custom domain

## Step 6: Monitoring and Logs

### View Logs
- Go to your Railway project dashboard
- Click on your service
- View real-time logs in the "Deployments" tab

### Monitor Performance
- Use the built-in Railway metrics
- Access your app's metrics endpoint: `/metrics`
- Set up external monitoring if needed

## Troubleshooting

### Common Issues

1. **Build Failures**:
   - Check that all dependencies are in `requirements.txt`
   - Verify Python version compatibility
   - Check build logs in Railway dashboard

2. **Runtime Errors**:
   - Verify all environment variables are set
   - Check application logs
   - Ensure database connection is working

3. **Health Check Failures**:
   - Verify the `/health` endpoint is working
   - Check if the application is binding to the correct port
   - Ensure all dependencies are installed

### Debug Commands

```bash
# Check Railway CLI status
railway status

# View logs
railway logs

# Connect to service shell
railway shell
```

## Environment-Specific Configurations

### Production Environment
- Set `DEBUG_MODE=false`
- Set `LOG_LEVEL=INFO` or `WARNING`
- Use strong secrets for `WEBHOOK_SECRET` and `JWT_SECRET`
- Enable rate limiting

### Development Environment
- Set `DEBUG_MODE=true`
- Set `LOG_LEVEL=DEBUG`
- Use test API keys
- Disable rate limiting if needed

## Security Considerations

1. **Environment Variables**:
   - Never commit sensitive data to your repository
   - Use Railway's environment variable system
   - Rotate secrets regularly

2. **API Security**:
   - Implement proper authentication
   - Use HTTPS (Railway provides this by default)
   - Validate webhook signatures

3. **Database Security**:
   - Use Supabase's built-in security features
   - Implement proper RLS (Row Level Security) policies
   - Regular security audits

## Scaling and Performance

### Railway Scaling
- Railway automatically handles basic scaling
- Monitor resource usage in the dashboard
- Upgrade plan if needed for higher resource limits

### Application Optimization
- Implement caching where appropriate
- Optimize database queries
- Use connection pooling
- Monitor response times

## Support and Resources

- **Railway Documentation**: [docs.railway.app](https://docs.railway.app)
- **Supabase Documentation**: [supabase.com/docs](https://supabase.com/docs)
- **FastAPI Documentation**: [fastapi.tiangolo.com](https://fastapi.tiangolo.com)

## Next Steps

After successful deployment:

1. **Set up monitoring**: Configure alerts for system health
2. **Implement CI/CD**: Set up automatic deployments from GitHub
3. **Add frontend**: Connect your frontend application
4. **Scale as needed**: Monitor usage and scale resources
5. **Security audit**: Regular security reviews and updates

Your AI Alert Triage System should now be successfully deployed and running on Railway! 🚀
